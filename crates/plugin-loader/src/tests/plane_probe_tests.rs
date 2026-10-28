// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane kind's host side under THE DESIGN §11.13 M1: a generation snapshot whose strings or
//! blobs state a length over the hard byte maximum is refused before any slice is formed over them,
//! and a door's facing binds, opens and refreshes its probe with the probes' lock let go.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;

/// RED (THE DESIGN §11.13 M1, "Every slice built from a plugin-reported length is capped and
/// validated before it is formed"; audit PL1 #1): a READY snapshot's `audience`, `openapi` or
/// `resource_facts` stated over the hard byte maximum (`u32::MAX`) refuses the snapshot before any
/// slice is formed or copied. Run in a child: a copy past the plugin's eight bytes kills the process.
#[test]
fn red_a_snapshot_length_over_the_byte_cap_is_refused_before_any_copy() {
    crate::dispatch_tests::assert_child_passes(
        "red_a_snapshot_length_over_the_byte_cap_is_refused_before_any_copy",
        "a snapshot length over the byte cap was copied",
        oversize_snapshot_lengths_child,
    );
}

/// The child half of the test above, in a process of its own.
fn oversize_snapshot_lengths_child() {
    use busbar_contract::abi::plane::PlaneSnapshot;
    let b = [b'a'; 8];
    let over = u32::MAX as usize + 1;
    let snap = || {
        // SAFETY: a `PlaneSnapshot` is plain C data (integers, raw pointers); all-zero is valid.
        let mut s: PlaneSnapshot = unsafe { std::mem::zeroed() };
        s.size = std::mem::size_of::<PlaneSnapshot>() as u32;
        s.generation = 1;
        s
    };
    let fine = snap();
    assert!(
        copy_snapshot(&fine, 0).is_some(),
        "a snapshot within every cap copies"
    );
    let mut audience = snap();
    audience.audience = AbiStr {
        ptr: b.as_ptr(),
        len: over,
    };
    assert!(
        copy_snapshot(&audience, 0).is_none(),
        "an audience over the cap"
    );
    let mut openapi = snap();
    openapi.openapi = Blob {
        ptr: b.as_ptr(),
        len: over,
        fmt: 0,
        flags: 0,
    };
    assert!(
        copy_snapshot(&openapi, 0).is_none(),
        "an openapi over the cap"
    );
    let mut facts = snap();
    facts.resource_facts = Blob {
        ptr: b.as_ptr(),
        len: over,
        fmt: 0,
        flags: 0,
    };
    assert!(
        copy_snapshot(&facts, 0).is_none(),
        "resource facts over the cap"
    );
}

/// A probe door double's park: armed, the next bind notes it entered and waits for the release (at
/// most thirty seconds, so a test that never releases fails rather than hangs).
#[derive(Default)]
struct Gate {
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
}

impl Gate {
    fn park(&self) {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return;
        }
        self.entered.store(true, Ordering::SeqCst);
        let since = Instant::now();
        while !self.released.load(Ordering::SeqCst) && since.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn entered_within(&self, wait: Duration) -> bool {
        let since = Instant::now();
        while !self.entered.load(Ordering::SeqCst) {
            if since.elapsed() > wait {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }
}

/// RED (THE DESIGN §11.13 M1, "No plugin code (`dlclose` included) runs under a host lock"; audit
/// PL1 #3): a door's facing for one public URL binds its probe (the door's load) and opens it. The
/// probe door double here parks in that bind: while it is parked, the facing for another URL is
/// answered, because the probes' lock is not held across the probe's plugin code.
#[test]
fn red_a_probe_is_bound_and_opened_with_the_probes_lock_let_go() {
    let gate = Arc::new(Gate::default());
    let parks = Arc::clone(&gate);
    let inner = linked_probe(crate::plane_door_plugin::door, "the-probe");
    let bind: ProbeBind = Arc::new(move || {
        parks.park();
        inner()
    });
    let reg = registration(bind).expect("the plane registers");
    gate.armed.store(true, Ordering::SeqCst);
    let (parked, second) = std::thread::scope(|s| {
        let first = Arc::clone(&reg.facing);
        let one = s.spawn(move || first(b"", b"", Some("https://one.example"), &[]).is_ok());
        let parked = gate.entered_within(Duration::from_secs(10));
        let (tx, rx) = std::sync::mpsc::channel();
        let other = Arc::clone(&reg.facing);
        s.spawn(move || {
            let _ = tx.send(other(b"", b"", Some("https://two.example"), &[]).is_ok());
        });
        let second = rx.recv_timeout(Duration::from_secs(5));
        // Released whatever happened, so the scope's join never waits on the parked bind.
        gate.released.store(true, Ordering::SeqCst);
        let _ = one.join();
        (parked, second)
    });
    assert!(parked, "the first facing never reached the probe's bind");
    assert!(
        second.is_ok(),
        "a facing blocked while another URL's probe was in its door: the probes' lock was held \
         across plugin code"
    );
}

/// LAW 7 FOR A PLANE'S REGISTRY ROW (`BUSBAR-1.6.0.md` l.1908-1910: "Core loads a plugin **iff**
/// its configuration section is present. No verb configured → that plugin is never loaded.";
/// reading a row's static declaration, its kind tail included, is reading, not loading).
///
/// RED before a linked door's registry row was read off its `'static` Statement: the row's facts
/// were read off a probe instance bound at registration, so every discovered plane was bound at boot
/// whatever the document wrote. Now the row binds nothing; the first judge of its section binds the
/// one probe that answers it.
#[test]
fn a_linked_plane_registry_row_binds_no_probe_until_its_section_is_judged() {
    use std::sync::atomic::AtomicUsize;
    let door = crate::plane_door_plugin::door;
    let binds = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&binds);
    let inner = linked_probe(door, "the-probe");
    let bind: ProbeBind = Arc::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        inner()
    });
    let candidate = crate::boot::Candidate::linked(door).expect("a linked door states itself");
    let reg = stated_registration(&candidate, bind).expect("the plane registers");
    assert_eq!(
        binds.load(Ordering::SeqCst),
        0,
        "registering a linked plane's row bound a probe instance of it"
    );
    let bound = registration(linked_probe(door, "the-probe")).expect("the plane binds");
    assert_eq!(
        reg.key, bound.key,
        "the stated row names the plane its bind does"
    );
    assert_eq!(reg.section, bound.section);
    assert_eq!(reg.owns, bound.owns);
    assert_eq!(reg.consumes, bound.consumes);
    assert_eq!(reg.requires, bound.requires);
    assert_eq!(reg.dialects, bound.dialects);
    assert_eq!(reg.admin_routes.len(), bound.admin_routes.len());
    let _ = (reg.validate)(b"");
    let _ = (reg.validate)(b"");
    assert_eq!(
        binds.load(Ordering::SeqCst),
        1,
        "judging its section binds the one probe that answers every judge"
    );
}
