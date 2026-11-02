// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Ordinary lifecycle ownership on the actual MCP image, both loading paths.
use crate::dispatch::kinds::plane::{open_door, refresh_door, retire_door, Plane};
use crate::dispatch::{
    load_dropped, load_linked, rendering_of, Adopter, Bind, ConnTable, LinkedRow, NoSink, Plugin,
};
use std::sync::Arc;
fn binding() -> Bind {
    Bind {
        instance: "mcp-lifecycle".into(),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: Adopter::unwatched(),
        conns: ConnTable::Probe,
    }
}
fn linked() -> Plugin<Plane> {
    load_linked::<Plane>(&LinkedRow::of(crate::actual_mcp::door).unwrap(), binding()).unwrap()
}
fn dropped() -> Plugin<Plane> {
    load_dropped::<Plane>(
        &crate::actual_mcp::cdylib(),
        &rendering_of(crate::actual_mcp::door).unwrap(),
        binding(),
    )
    .unwrap()
}
#[test]
fn repeated_plane_loads_reuse_owned_static_words_after_the_image_is_released() {
    for make in [linked as fn() -> Plugin<Plane>, dropped] {
        let first = make();
        let a = first.served();
        let declared = first.declared();
        drop(first);
        let second = make();
        let b = second.served();
        assert_eq!(a.section, b.section);
        assert_eq!(a.op_classes, b.op_classes);
        assert!(
            std::ptr::eq(a.section, b.section),
            "same declaration has one permanent word copy"
        );
        assert!(!a.op_classes.is_empty());
        assert!(std::ptr::eq(a.op_classes[0], b.op_classes[0]));
        assert!(!declared.record_kinds.is_empty());
        assert!(std::ptr::eq(
            declared.record_kinds[0],
            second.declared().record_kinds[0]
        ));
        drop(second);
        assert_eq!(a.section, "tools");
        assert!(!a.op_classes.is_empty());
        assert_eq!(declared.record_kinds.len(), 4);
    }
}
#[test]
fn the_hosts_snapshot_copy_survives_the_actual_plugins_next_refresh() {
    for p in [linked(), dropped()] {
        let first = open_door(&p, b"{}", b"{}", None).unwrap();
        let published = first.clone();
        assert_eq!(first.generation, 1);
        let second = refresh_door(&p, b"{}", b"{}", 2).unwrap();
        assert_eq!(second.generation, 2);
        retire_door(&p, 1);
        assert_eq!(
            first, published,
            "generation1 owned copy outlives its retire"
        );
    }
}
#[test]
fn facing_replaces_old_open_inputs_and_closes_its_last_probe() {
    for make in [linked as fn() -> Plugin<Plane>, dropped] {
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = held.clone();
        let bind = Arc::new(move || {
            let p = make();
            observed.lock().unwrap().push(p.inner.clone());
            Ok(p)
        });
        let reg = crate::dispatch::kinds::plane::registration(bind).unwrap();
        let first = (reg.facing)(b"{}", b"", Some("https://one.example"), &[]).unwrap();
        let first_copy = first.clone();
        let again = (reg.facing)(b"{}", b"", Some("https://one.example"), &[]).unwrap();
        assert_eq!(again, first);
        assert_eq!(
            held.lock().unwrap().len(),
            2,
            "same inputs refresh existingprobe"
        );
        (reg.facing)(b"{}", b"{}", Some("https://two.example"), &[]).unwrap();
        assert!(!held.lock().unwrap()[1].is_open(), "supersededinput closed");
        (reg.facing)(b"{}", b"", Some("https://one.example"), &[]).unwrap();
        assert!(!held.lock().unwrap()[2].is_open(), "secondinput closed");
        assert_eq!(first, first_copy, "ownedfacing survivesprobeclose");
        let last = reg.facing.clone();
        drop(reg);
        assert!(held.lock().unwrap()[3].is_open(), "facing owner exists");
        drop(last);
        assert!(
            held.lock().unwrap().iter().all(|p| !p.is_open()),
            "lastowner closesprobe"
        );
    }
}
