// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::root::registry::{Dropped, DroppedDoor};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};

type Inventory = Mutex<Option<Dropped>>;

struct ClosingDoor {
    inner: Arc<dyn FramerDoor>,
    inventory: Weak<Inventory>,
    closes: Arc<AtomicUsize>,
}

impl FramerDoor for ClosingDoor {
    fn facts(&self) -> &DoorFacts {
        self.inner.facts()
    }
    fn cross(&self, call: Call<'_>) -> Crossed {
        self.inner.cross(call)
    }
}

impl Drop for ClosingDoor {
    fn drop(&mut self) {
        let inventory = self.inventory.upgrade().unwrap();
        assert!(
            inventory.try_lock().is_ok(),
            "a retired door closes outside the host inventory lock"
        );
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
}

fn opened(settings: &TransportSettings) -> Arc<dyn FramerDoor> {
    let plugin =
        crate::root::test_plugins::linked_transport(busbar_transport_http::door::door, crate::root::doors::bind());
    Arc::new(crate::root::doors::Dispatched::open(plugin, settings).unwrap())
}

fn inventory(door: Arc<dyn FramerDoor>) -> Dropped {
    let key = door.facts().claims[0];
    let wire = Arc::new(busbar_core_connector::wire::HostWire::new(door.as_ref()).unwrap());
    Dropped {
        doors: std::borrow::Cow::Owned(vec![DroppedDoor {
            key,
            claims: vec![key],
            composes_over: Vec::new(),
            offered: busbar_contract::abi::auth::AuthPoints::default(),
            upgrades: Vec::new(),
            wire,
            door,
        }]),
    }
}

#[test]
fn replacing_a_cached_inventory_releases_old_doors_after_its_snapshot_and_outside_the_lock() {
    let cache = Arc::new(Inventory::new(None));
    let closes = Arc::new(AtomicUsize::new(0));
    let base = opened(&TransportSettings::default());
    let base_life = Arc::downgrade(&base);
    let closing: Arc<dyn FramerDoor> = Arc::new(ClosingDoor {
        inner: base,
        inventory: Arc::downgrade(&cache),
        closes: Arc::clone(&closes),
    });
    super::publish_transport_inventory(&cache, inventory(closing));
    let snapshot = cache.lock().unwrap().clone().unwrap();
    let effective = TransportSettings {
        request_timeout_secs: 7,
        ..TransportSettings::default()
    };
    super::publish_transport_inventory(&cache, inventory(opened(&effective)));
    assert!(
        base_life.upgrade().is_some(),
        "the outstanding snapshot retains its actual base door"
    );
    assert_eq!(closes.load(Ordering::SeqCst), 0);
    drop(snapshot);
    assert!(
        base_life.upgrade().is_none(),
        "the obsolete cache has no permanent strong holder"
    );
    assert_eq!(closes.load(Ordering::SeqCst), 1);
}
