// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE RIDES THE REAL HOST, ON THE ONE PATH: a door plane, loaded both ways through the
//! one loader seam (compiled in by `load_linked`, dropped in by `load_dropped`),
//! crosses into the KERNEL's own host services on the one dispatcher, and the two doors answer
//! alike.
//!
//! It replaces the kernel's former plane-ABI rider, which drove the retiring dlopen lane's plane
//! table from inside the kernel and so had to name the loader. What that rider proved, and where
//! each claim now stands:
//! - a dropped-in plane serves over the real host table: here, both doors, on the kernel's services
//!   ([`a_door_plane_reads_the_kernels_own_clock_both_ways`]);
//! - the host's answer is the host's, not one the plane made up: the clock reading lies inside the
//!   kernel's own readings taken around the call (same test);
//! - each host crossing is load-bearing: with no host services bound the plane's clock read is
//!   refused and the arrival refuses ([`with_no_host_services_the_clock_read_is_refused`]);
//! - a crossing happens exactly once per call: the plane counts its own host calls, one per read;
//! - pricing blindness: a door plane reports unit counts (class, source, amount) and the ABI carries
//!   no price field at all, which the plane driver's own money-seam tests read off every answer;
//! - the per-slot vtable counts, the metering lease round trip and the signed-tarball delivery of a
//!   dlopen-lane plane die with that lane (its host table and its registry `open_plane` are
//!   deleted by the old-loader removal); the door lane's delivery path is the one-dispatcher boot's
//!   door-plane load, proven there.

#[path = "fixtures/plane_driver_test_plane.rs"]
#[allow(dead_code)]
mod plane;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome as AbiOutcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::{KindCode, MECHANISM_VERSION};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, PlaneOpenIn, PlaneOpenOut, UnitCount,
};
use busbar_contract::services::HostServices;
use busbar_kernel::host_services::{KernelServices, SystemResolver};

use busbar_plugin_loader::dispatch::{
    in_head, kinds::plane::Plane, load_dropped, load_linked, out_head, Bind, DispatchConfig,
    Dispatcher, Frame, ManifestFacts, NoSink, Plugin, NO_BLOB,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    Linked,
    Dropped,
}

/// The test plane's `cdylib`, built as the busbar `plane_driver_test_plane` example.
fn dropped_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}plane_driver_test_plane{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let found = path.exists().then_some(path);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the plane_driver_test_plane example cdylib is not built under CI"
    );
    found
}

fn ways() -> Vec<Way> {
    let mut ways = vec![Way::Linked];
    if dropped_path().is_some() {
        ways.push(Way::Dropped);
    }
    ways
}

/// Load and open the test plane through `way` on `dispatcher`.
fn opened(way: Way, dispatcher: &Dispatcher) -> Plugin<Plane> {
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
    };
    let plugin = match way {
        Way::Linked => load_linked::<Plane>(plane::door, bind).expect("the linked door loads"),
        Way::Dropped => {
            let facts = ManifestFacts {
                mechanism_version: MECHANISM_VERSION,
                kind: KindCode::Plane,
                kind_abi: KindCode::Plane.abi_version(),
            };
            let path = dropped_path().expect("the example is built");
            load_dropped::<Plane>(&path, &facts, bind).expect("the dropped door loads")
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
            },
            public_url: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
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

/// `arrive` on `target`: its outcome and the unit amounts it wrote.
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
            _reserved: 0,
        },
    );
    let outcome = plugin.call(slot::ARRIVE, &mut frame).outcome;
    let written = frame.out.units_written as usize;
    (outcome, units[..written].iter().map(|u| u.amount).collect())
}

/// The plane's own count of the calls it made into the host.
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
    let services = Arc::new(KernelServices::new(
        HashMap::new(),
        Arc::new(SystemResolver),
    ));
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
