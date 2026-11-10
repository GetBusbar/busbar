// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{Bind, ConnTable, DispatchConfig, LinkedRow, NoSink};
use busbar_contract::abi::export::{CheckOut, ExportStream, Tail};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::export::{tail, NoScrape, NoServe, Quiet};
use busbar_contract::abi::sdk::life::{Held, Life, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::plugin::markers::ExportKind;

struct Neutral(Vec<u8>);
impl Life for Neutral {
    type Kind = ExportKind;
    const CANCEL: u32 = 0;
    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self(settings.to_vec()))
    }
}
struct Declare;
impl SafeSlot for Declare {
    type Kind = ExportKind;
    type In = CheckIn;
    type Out = CheckOut;
    type State = Held<Neutral>;
    fn call(
        instance: Instance<'_, Held<Neutral>, ExportKind>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        assert_eq!(
            input.phase,
            busbar_contract::abi::export::CHECK_PHASE_RECORDER
        );
        let h = instance.get().unwrap();
        match h.life().0.as_slice() {
            b"refuse" => return out.fail(Refusal::refused("no declaration")),
            b"absent" => return Outcome::Ready,
            bytes => out.lease(|o| &o.findings, h.leases(), bytes.to_vec(), BLOB_JSON),
        }
        Outcome::Ready
    }
}
struct Deliver;
impl SafeSlot for Deliver {
    type Kind = ExportKind;
    type In = DeliverIn;
    type Out = busbar_contract::abi::mechanism::call::OutHead;
    type State = Held<Neutral>;
    fn call(
        _: Instance<'_, Held<Neutral>, ExportKind>,
        _: Lent<'_, DeliverIn>,
        _: Out<'_, Self::Out>,
    ) -> Outcome {
        Outcome::Ready
    }
}
const TAIL: Tail = tail(&[ExportStream::Metrics as u8], &[]);
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::export_calls::EXT_RECORDER_REQUIREMENTS, b"1"),
]);
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    extensions: EXTENSIONS,
    ..statement("neutral-recorder", "0.0.1", 4)
};
busbar_contract::plugin_door! {
    ops: busbar_contract::abi::export::Ops,
    statement: STATEMENT,
    lifecycle: life(Neutral),
    kind_ops: {
        deliver: Safe<Deliver>, scrape: Safe<NoScrape<Neutral>>,
        status: Safe<Quiet<Neutral>>, check: Safe<Declare>, serve: Safe<NoServe<Neutral>>,
    },
}

fn open(settings: &[u8]) -> Result<ExportInstance, String> {
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let row = LinkedRow::of(door).unwrap();
    let p = crate::dispatch::load_linked::<Export>(
        &row,
        Bind {
            instance: Arc::from("export.neutral"),
            max_inflight_cap: 4,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Probe,
        },
    )
    .unwrap();
    ExportInstance::open(p, d, settings)
}

#[test]
fn advertised_recorder_declarations_fail_closed_after_open() {
    for bad in [
        b"absent".as_slice(),
        b"refuse",
        b"{}",
        b"null",
        b"[]",
        br#"{"retention_seconds":0,"key_gauge_limit":0}"#,
        br#"{"retention_seconds":1,"key_gauge_limit":0,"vendor_key":5}"#,
    ] {
        assert!(
            open(bad).is_err(),
            "accepted {}",
            String::from_utf8_lossy(bad)
        );
    }
    assert!(open(&vec![b' '; 1025]).is_err());
    let instance = open(br#"{"retention_seconds":17,"key_gauge_limit":3}"#).unwrap();
    assert_eq!(
        instance.recorder_requirements(),
        Some(busbar_contract::export_calls::RecorderRequirements {
            retention_seconds: 17,
            key_gauge_limit: 3,
        })
    );
}

#[test]
fn config_probe_carries_the_declaration_or_reports_its_refusal() {
    let manifest = crate::both_ways::statement(
        "export",
        "neutral-recorder",
        "neutral-recorder",
        busbar_contract::abi::export::ABI_VERSION,
    );
    let registry = crate::PluginRegistry::empty()
        .link(vec![crate::LinkedPlugin::door(manifest, door)])
        .unwrap();
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let rows = crate::export_axis::ExportRows::new(&registry, d);
    let (streams, problems, recorder) = rows
        .probe(
            "neutral-recorder",
            "any-name",
            &crate::dispatch::test_settings(
                &serde_json::json!({"retention_seconds":23,"key_gauge_limit":4}),
            ),
        )
        .unwrap();
    assert_eq!(streams, Some(vec![ExportStream::Metrics as u8]));
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(recorder.unwrap().retention_seconds, 23);
    let (_, problems, recorder) = rows
        .probe(
            "neutral-recorder",
            "any-name",
            &crate::dispatch::test_settings(&serde_json::json!({})),
        )
        .unwrap();
    assert!(recorder.is_none());
    assert!(!problems.is_empty());
}
