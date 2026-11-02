// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observe a real linked plane's Pending piece calls without replacing its behavior.
//!
//! The root fixture must supply the plane's genuine macro descriptor alongside the door selected
//! from its linked registration. A bare door function cannot grant this capability:
//!
//! ```compile_fail
//! use busbar_contract::abi::mechanism::door::DoorFn;
//! use busbar_test_kit::root_door_fixtures::piece_pending::select;
//! fn unproven(door: DoorFn) -> DoorFn { select(door, door) }
//! ```
//!
//! ```no_run
//! use busbar_contract::abi::{mechanism::door::DoorFn, sdk::door::MacroDoor};
//! use busbar_test_kit::root_door_fixtures::piece_pending::select;
//! fn proven(descriptor: MacroDoor, selected: DoorFn) -> DoorFn {
//!     select(descriptor, selected)
//! }
//! ```

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use busbar_contract::abi::mechanism::call::{InHead, Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{self, OnPieceIn, Ops};
use busbar_contract::abi::sdk::door::MacroDoor;

use crate::test_support::DoorView;

static ACTIVE: Mutex<Option<Arc<Observation>>> = Mutex::new(None);
static WRAPPED: OnceLock<Wrapped> = OnceLock::new();

#[derive(Debug, Default)]
struct Observation {
    owner: AtomicU64,
    armed: AtomicBool,
    waiter: AtomicU64,
}

/// One observation, installed while the root's publishing fixture is held exclusively.
/// Dropping it removes only this observation, including during assertion unwind.
#[derive(Debug)]
pub struct Watching(Arc<Observation>);

impl Watching {
    /// Install a fresh observation. A second simultaneous observation is rejected.
    #[must_use]
    pub fn install() -> Self {
        let observation = Arc::new(Observation::default());
        let mut active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(active.is_none(), "one piece observer at a time");
        *active = Some(Arc::clone(&observation));
        Self(observation)
    }

    /// Arm waiter observation after the delayed owner has entered its actual piece callback.
    pub fn arm_after_owner_held(&self) {
        assert_ne!(
            self.0.owner.load(Ordering::SeqCst),
            0,
            "the delayed owner entered an ATTEMPT callback"
        );
        self.0.armed.store(true, Ordering::SeqCst);
    }

    /// Whether another eligible unit's real callback returned Pending after arming.
    #[must_use]
    pub fn waiter_pending(&self) -> bool {
        self.0.waiter.load(Ordering::SeqCst) != 0
    }
}

impl Drop for Watching {
    fn drop(&mut self) {
        let retired = {
            let mut active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
            if active
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &self.0))
            {
                active.take()
            } else {
                None
            }
        };
        drop(retired);
    }
}

struct Wrapped {
    source: DoorFn,
    original: Op,
    door: Door,
}

// SAFETY: construction requires the genuine MacroDoor. The copied table is leaked immutable;
// its Statement, nested ranges and function pointers retain that descriptor's static backing.
unsafe impl Send for Wrapped {}
// SAFETY: the owned door and every referenced descriptor/table entry remain immutable after publish.
unsafe impl Sync for Wrapped {}

impl Wrapped {
    fn new(proven: MacroDoor) -> Self {
        let view = DoorView::of(proven);
        let real = view.door();
        assert_eq!(real.kind(), KindCode::Plane as u32);
        assert_eq!(real.kind_abi(), KindCode::Plane.abi_version());
        assert_eq!(real.layout(), KindCode::Plane.layout_fingerprint());
        let mut ops = *view.ops::<Ops>();
        assert_eq!(ops.head.slots, plane::SLOTS);
        assert_eq!(ops.head.size as usize, std::mem::size_of::<Ops>());
        let original = ops.on_piece.expect("the real plane implements on_piece");
        ops.on_piece = Some(on_piece);
        let ops = Box::leak(Box::new(ops));
        // SAFETY: the genuine macro descriptor proves the complete immutable static Statement
        // and table. All slots remain original except this same-ABI delegating ON_PIECE wrapper;
        // the copied table is process-lived and does not borrow this owned Door's address.
        let door = unsafe {
            Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                ops: std::ptr::from_ref(ops).cast(),
                ..real.parts()
            })
            .__with_migrate(real.migrate())
        };
        Self {
            source: proven.door_fn(),
            original,
            door,
        }
    }
}

/// Select the observed door only while watching, after checking the root selected this exact
/// macro-origin function. Unobserved fixtures receive their real door unchanged.
///
/// One original plane is supported per process; another original is rejected before any crossing.
#[must_use]
pub fn select(proven: MacroDoor, selected: DoorFn) -> DoorFn {
    assert!(
        std::ptr::fn_addr_eq(proven.door_fn(), selected),
        "the macro descriptor must name the root's selected linked door"
    );
    if ACTIVE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_none()
    {
        return selected;
    }
    let wrapped = WRAPPED.get_or_init(|| Wrapped::new(proven));
    assert!(
        std::ptr::fn_addr_eq(wrapped.source, selected),
        "one original plane per piece observer"
    );
    observed_door
}

extern "C" fn observed_door() -> &'static Door {
    &WRAPPED
        .get()
        .expect("select initialized the immutable door")
        .door
}

extern "C" fn on_piece(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    let observation = ACTIVE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let attempt = if input.is_null() {
        None
    } else {
        // SAFETY: this slot receives the host's initialized, aligned InHead-prefixed frame.
        let head = unsafe { &*input.cast::<InHead>() };
        if head.size as usize >= std::mem::size_of::<OnPieceIn>()
            && head.op == plane::slot::ON_PIECE
        {
            // SAFETY: the unchanged ON_PIECE host frame covers this exact borrowed type. No
            // nested pointer is dereferenced or retained, and the borrow ends before delegation.
            let piece = unsafe { &*input.cast::<OnPieceIn>() };
            (piece.from == plane::FROM_KERNEL && piece.flags & plane::PIECE_REFUSED == 0)
                .then_some(piece.unit)
        } else {
            None
        }
    };
    if let (Some(observation), Some(unit)) = (&observation, attempt) {
        let _ = observation
            .owner
            .compare_exchange(0, unit, Ordering::SeqCst, Ordering::SeqCst);
    }
    let original = WRAPPED.get().expect("the wrapper was initialized").original;
    // SAFETY: preserve this genuine macro slot's exact live instance, typed host frames and
    // nested loans. Delegate exactly once without changing any byte; its actual return decides.
    let outcome = unsafe { original(instance, input, out) };
    if outcome.outcome() == Outcome::Pending {
        if let (Some(observation), Some(unit)) = (&observation, attempt) {
            if observation.armed.load(Ordering::SeqCst)
                && unit != observation.owner.load(Ordering::SeqCst)
            {
                let _ = observation.waiter.compare_exchange(
                    0,
                    unit,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
        }
    }
    outcome
}
