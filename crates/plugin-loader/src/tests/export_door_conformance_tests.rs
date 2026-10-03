// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: export`, BOTH WAYS, THROUGH THE ONE DISPATCHER** (TODO ABI-b4; M6/contract). The export
//! kind's REAL shipped sink on the memory ABI, the prometheus sink from its own repo at the rev the
//! workspace pins (the one sink with no network), is loaded LINKED (its logic crate's door, compiled
//! into this build) and DROPPED IN (its `-plugin` crate's `cdylib`, built from the pinned checkout
//! and `dlopen`ed) and driven over ONE script of the kind's table through [`ExportInstance`]:
//! `validate` and `open` (one crossing each), a `scrape` that fits (one), a `scrape` too large for
//! the first buffer (two: the call and the re-call a short answer earns), `status` and `serve`, which
//! the sink does not serve (one each, answered REFUSED), and `check` (one). The two transcripts must
//! be equal, line for line, and each door must have made EXACTLY [`CROSSINGS`] crossings: not
//! "above zero", the count the script's calls make.
//!
//! M6/contract asks for the SHIPPED binary: the proof is run with `--release` and the cdylib built
//! `--release`; nothing here is profile-dependent, so the exact count holds in either profile. A
//! missing cdylib is a FAILURE here, never a skip: this suite is the kind's finish line.
//!
//! RED ARMS, KEPT: [`the_count_rule_refuses_a_count_off_by_one`] shows the exact-count rule failing on
//! a count one too high or one too low; [`a_door_is_not_a_dropped_in_door_until_it_is_loaded_from_its_cdylib`]
//! shows the dropped-in leg is the built cdylib (a path that is not it is refused).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use busbar_contract::abi::export::CHECK_PHASE_INSTANCES;
use busbar_contract::export_calls::{parse_families, ExportCalls, ServeRequest};

use crate::both_ways;
use crate::dispatch::kinds::export::Export;
use crate::dispatch::Plugin;
use crate::dispatch::{load_dropped, rendering_of, DispatchConfig, Dispatcher};
use crate::door_both_ways::bind;
use crate::export_door::{check, ExportInstance};

/// The settings the sink opens on.
const SETTINGS: &[u8] = br#"{"buffer_seconds":60}"#;

/// The crossings the script makes, counted by hand: validate, open (2); a scrape that fits (1); a
/// scrape past the first buffer, its call and its one re-call (2); status, REFUSED (1); serve,
/// REFUSED (1); check (1).
const CROSSINGS: u64 = 8;

/// The crossings `p` has made.
fn crossings(p: &Plugin<Export>) -> u64 {
    p.inner.crossings.load(Ordering::Relaxed)
}

/// The exact-count rule: `counted` is `pinned`, or the leg `who` says how it is not.
fn exact(who: &str, counted: u64, pinned: u64) -> Result<(), String> {
    if counted == pinned {
        Ok(())
    } else {
        Err(format!("{who}: {counted} crossings, pinned {pinned}"))
    }
}

/// A small recorder snapshot, and one larger than the first exposition buffer.
fn expositions() -> (String, String) {
    let small = "# TYPE busbar_requests_total counter\nbusbar_requests_total{pool=\"a\"} 3\n\n";
    let mut big = String::from("# TYPE busbar_big counter\n");
    for i in 0..4000 {
        big.push_str(&format!("busbar_big{{n=\"{i:020}\"}} {i}\n"));
    }
    big.push('\n');
    (small.to_string(), big)
}

/// THE SCRIPT over one opened instance, one line per answer; the crossings the plugin made.
fn script(sink: &ExportInstance) -> (Vec<String>, u64) {
    let (small, big) = expositions();
    let mut t = Vec::new();
    for text in [&small, &big] {
        let families = parse_families(text).expect("the snapshot reads");
        let body = sink.scrape(&families).expect("the sink renders");
        t.push(format!(
            "scrape: {} bytes, equal={}",
            body.len(),
            body == text.as_bytes()
        ));
    }
    t.push(format!("status: {:?}", sink.status()));
    let req = ServeRequest {
        method: "GET",
        path: "/metrics",
        query: None,
        headers: &[],
        body: &[],
    };
    t.push(format!("serve: refused={}", sink.serve(&req).is_err()));
    t.push(format!(
        "check: {:?}",
        check(
            sink.plugin(),
            CHECK_PHASE_INSTANCES,
            &[("metrics".into(), SETTINGS.to_vec())]
        )
    ));
    (t, crossings(sink.plugin()))
}

/// The shipped sink, LINKED: its door, through the one dispatcher; opened.
fn linked() -> ExportInstance {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = crate::dispatch::LinkedRow::of(busbar_export_prometheus::door::door)
        .expect("the door states its Statement");
    let plugin = crate::dispatch::load_linked::<Export>(&row, bind(&dispatcher))
        .expect("the linked door loads");
    ExportInstance::open(plugin, dispatcher, SETTINGS).expect("the linked sink opens")
}

/// The shipped sink, DROPPED IN: its built `cdylib`, against the rendering the linked door states.
fn dropped() -> ExportInstance {
    let path = both_ways::cdylib("busbar_export_prometheus_plugin")
        .expect("the prometheus sink's cdylib is built");
    dropped_from(&path).expect("the dropped-in door loads")
}

fn dropped_from(path: &std::path::Path) -> Result<ExportInstance, String> {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let stated = rendering_of(busbar_export_prometheus::door::door).expect("the door renders");
    let plugin =
        load_dropped::<Export>(path, &stated, bind(&dispatcher)).map_err(|e| format!("{e:?}"))?;
    ExportInstance::open(plugin, dispatcher, SETTINGS)
}

#[test]
fn a_linked_and_a_dropped_in_export_sink_answer_identically_with_exact_crossings() {
    let (a, linked_crossings) = script(&linked());
    let (b, dropped_crossings) = script(&dropped());
    assert_eq!(a, b, "the two doors answer the same, line for line");
    // `open` made validate + open before the script's own calls.
    exact("linked", linked_crossings, CROSSINGS).unwrap();
    exact("dropped in", dropped_crossings, CROSSINGS).unwrap();
    // The script reached every answer it names: equal empty transcripts would prove nothing.
    assert!(a[0].contains("equal=true"), "{}", a[0]);
    assert!(a[1].contains("equal=true"), "a re-called scrape: {}", a[1]);
    assert_eq!(a[2], "status: None");
    assert_eq!(a[3], "serve: refused=true");
    assert!(a[4].contains("Ok([])"), "{}", a[4]);
}

/// THE RED ARM, KEPT: the rule fails a count one too high or one too low.
#[test]
fn the_count_rule_refuses_a_count_off_by_one() {
    assert!(exact("x", CROSSINGS, CROSSINGS).is_ok());
    assert!(exact("x", CROSSINGS, CROSSINGS + 1).is_err());
    assert!(exact("x", CROSSINGS - 1, CROSSINGS).is_err());
}

/// THE RED ARM, KEPT: the dropped-in leg is the built cdylib; a path that is not one is refused.
#[test]
fn a_door_is_not_a_dropped_in_door_until_it_is_loaded_from_its_cdylib() {
    let refused = dropped_from(std::path::Path::new(
        "/nonexistent/libbusbar_export_prometheus_plugin.so",
    ));
    assert!(refused.is_err(), "a missing image does not load");
}
