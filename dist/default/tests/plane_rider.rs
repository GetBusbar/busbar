// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

#[path = "../../../crates/busbar/src/root/tests/test_plugins.rs"]
mod fixture_plugins;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome as AbiOutcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, PlaneOpenIn, PlaneOpenOut, UnitCount,
};
use busbar_contract::services::HostServices;
use busbar_kernel::host_services::KernelServices;

use busbar_plugin_loader::dispatch::{
    in_head, kinds::plane::Plane, load_dropped, load_linked, out_head, rendering_of, Bind,
    DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink, Plugin, NO_BLOB,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    Linked,
    Dropped,
}

fn dropped_path() -> std::path::PathBuf {
    let name = "plane_driver_test_plane";
    let exe = std::env::current_exe().expect("the test binary's path");
    let path = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary sits in target/<profile>/deps")
        .join("examples")
        .join(format!(
            "{}{name}{}",
            std::env::consts::DLL_PREFIX,
            std::env::consts::DLL_SUFFIX
        ));
    if !path.exists() {
        fixture_plugins::missing(name, fixture_plugins::BUILD_BUSBAR_EXAMPLES);
    }
    path
}

fn ways() -> Vec<Way> {
    vec![Way::Linked, Way::Dropped]
}

fn opened(way: Way, dispatcher: &Dispatcher) -> Plugin<Plane> {
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),

        conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
    };
    let plugin = match way {
        Way::Linked => {
            let row = LinkedRow::of(plane::door).expect("the plane states its Statement");
            load_linked::<Plane>(&row, bind).expect("the linked door loads")
        }
        Way::Dropped => {
            let stated = rendering_of(plane::door).expect("the plane renders its Statement");
            let path = dropped_path();
            load_dropped::<Plane>(&path, &stated, bind).expect("the dropped door loads")
        }
    };
    let mut open = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: NO_BLOB,
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            public_url: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            owned: NO_BLOB,
            providers: std::ptr::null(),
            providers_len: 0,
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
            snapshot: std::ptr::null(),
        },
    );
    assert_eq!(
        plugin.call(life::OPEN, &mut open).outcome,
        AbiOutcome::Ready
    );
    plugin
}

fn arrive(plugin: &Plugin<Plane>, target: &[u8]) -> (AbiOutcome, Vec<u64>) {
    let mut units = [UnitCount {
        class: 0,
        source: 0,
        amount: 0,
    }; 8];
    let mut frame = Frame::new(
        ArriveIn {
            head: in_head(),
            unit: 0,
            claim: 0,
            _reserved: 0,
            target: AbiStr {
                ptr: target.as_ptr(),
                len: target.len(),
            },
            fields: std::ptr::null(),
            fields_len: 0,
            body: NO_BLOB,
            units_buf: units.as_mut_ptr(),
            units_cap: units.len(),
            method: AbiStr {
                ptr: b"GET".as_ptr(),
                len: 3,
            },
        },
        ArriveOut {
            head: out_head(),
            op_class: 0,
            principal_need: 0,
            dialect: 0,
            units_written: 0,
            units_needed: 0,
            refusal: 0,
            refusal_status: 0,
            refusal_flags: 0,
            correlation: 0,
            cancels: 0,
            pool: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            route: 0,
            route_flags: 0,
            _route_reserved: [0; 6],
            affinity: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            trust_counterparty: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            trust_item: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
            trust_digest: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        },
    );
    let outcome = plugin.call(slot::ARRIVE, &mut frame).outcome;
    let written = frame.out.units_written as usize;
    (outcome, units[..written].iter().map(|u| u.amount).collect())
}

fn host_calls(plugin: &Plugin<Plane>) -> u64 {
    arrive(plugin, b"/stats").1[plane::Stat::HostCalls as usize]
}

fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

#[test]
fn a_door_plane_reads_the_kernels_own_clock_both_ways() {
    let services = Arc::new(KernelServices::new());
    let dispatcher = Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::clone(&services) as Arc<dyn HostServices>,
    );
    let mut answers = Vec::new();
    for way in ways() {
        let plugin = opened(way, &dispatcher);
        let calls = host_calls(&plugin);
        let (before, mono_before) = (wall_ns(), services.now().mono_ns);
        let (outcome, read) = arrive(&plugin, b"/clock");
        let (after, mono_after) = (wall_ns(), services.now().mono_ns);
        assert_eq!(
            outcome,
            AbiOutcome::Ready,
            "{way:?}: the host answered the clock"
        );
        assert!(
            (before..=after).contains(&read[0]),
            "{way:?}: the wall reading is the host's, taken during the call"
        );
        assert!(
            (mono_before..=mono_after).contains(&read[1]),
            "{way:?}: the monotonic reading is on the kernel's own origin"
        );
        assert!(
            read[1] < read[0],
            "{way:?}: wall and monotonic are two different readings, not one amount twice"
        );
        let (_, again) = arrive(&plugin, b"/clock");
        assert!(
            again[0] >= read[0] && again[1] >= read[1],
            "{way:?}: a later read of the kernel's clock never runs backwards"
        );
        assert_eq!(
            host_calls(&plugin),
            calls + 2,
            "{way:?}: each read crosses into the host exactly once"
        );
        answers.push(outcome);
    }
    answers.dedup();
    assert_eq!(answers.len(), 1, "both doors answer alike");
}

#[test]
fn with_no_host_services_the_clock_read_is_refused() {
    let dispatcher = Dispatcher::new(DispatchConfig::default());
    for way in ways() {
        let plugin = opened(way, &dispatcher);
        assert_eq!(
            arrive(&plugin, b"/clock").0,
            AbiOutcome::Refused,
            "{way:?}: the host crossing is load-bearing"
        );
    }
}
