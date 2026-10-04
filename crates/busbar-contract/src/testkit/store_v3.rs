// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIND'S SHARED EPOCH AND SLICE-LIFE CASES (`abi::store::SLICE_TTL_MS`, the store kind's
//! spec). Every store a FLEET shares runs [`fleet_store`] from its own tests, through a [`Harness`]
//! that opens its store over one durable state and moves its clock. A node-local store runs
//! [`single_node_store`] instead. Each case panics naming the rule it found broken.

use crate::abi::sdk::store::{Cap, Cell, CellKey, Dimension, Op, ReserveRefused, Step, StoreSlots};
use crate::abi::store::{OpId, SLICE_TTL_MS};

/// A direct call's answer: these cases call on no ticket, where a store may not pend.
fn ready<T>(step: Step<T>) -> T {
    match step {
        Step::Ready(t) => t,
        Step::Pending { .. } => panic!("a store answered PENDING to a call on no ticket"),
    }
}

/// What a store's tests hand the cases: its store over ONE durable state, and its clock.
pub trait Harness {
    /// The store under test.
    type Store: StoreSlots;
    /// Open the store over the harness's durable state. A second call is a RESTART: same state,
    /// a fresh instance.
    fn open(&self) -> Self::Store;
    /// The store's clock, in ms.
    fn now_ms(&self) -> u64;
    /// Move the store's clock forward by `ms`.
    fn advance_ms(&self, ms: u64);
}

/// The cases' own `op_id`s. The node half is one no store mints under, distinct per case, so cases
/// run over ONE durable state never repeat an id; the counter is the case's own (the contract
/// holds no state: contract-stateless).
struct Ops {
    node: u64,
    next: std::cell::Cell<u64>,
}

impl Ops {
    /// The ids of case number `case`.
    fn case(case: u64) -> Self {
        Ops {
            node: 0x7e57_ca50 + case,
            next: std::cell::Cell::new(0),
        }
    }

    fn op(&self) -> OpId {
        let n = self.next.get() + 1;
        self.next.set(n);
        OpId::from_parts(self.node, n)
    }
}

fn key(bucket: &str) -> CellKey<'_> {
    CellKey {
        bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start: 1_790_000_000_000,
    }
}

/// Cap `bucket` at `cap`.
fn capped<S: StoreSlots>(ops: &Ops, s: &S, bucket: &str, cap: u64) {
    let caps = [Cap {
        key: key(bucket),
        cap,
        config_gen: 1,
    }];
    ready(s.window_caps(&mut Op::detached(), ops.op(), &caps)).expect("the cap is pushed");
}

fn draw<S: StoreSlots>(
    ops: &Ops,
    s: &S,
    bucket: &str,
    amount: u64,
    epoch: u64,
) -> Result<crate::abi::sdk::store::Grant, ReserveRefused> {
    let cells = [Cell {
        key: key(bucket),
        amount,
    }];
    let mut grants = Vec::new();
    ready(s.reserve(
        &mut Op::detached(),
        ops.op(),
        epoch,
        cells.iter().copied(),
        &mut grants,
    ))
    .map(|()| grants.into_iter().next().expect("one grant per cell"))
}

/// Release `unspent` of `slice` under `epoch`: the amount the store took back.
fn release<S: StoreSlots>(
    ops: &Ops,
    s: &S,
    epoch: u64,
    slice: u64,
    unspent: u64,
) -> Result<u64, String> {
    let mut back = Vec::new();
    let items = [(slice, unspent)].into_iter();
    ready(s.slice_release(&mut Op::detached(), ops.op(), epoch, items, &mut back))
        .map_err(|e| format!("{e:?}"))?;
    Ok(back.into_iter().next().expect("one amount per item"))
}

/// A reserve under an epoch below the stored one is StaleEpoch and applies nothing.
pub fn stale_epoch_refused<H: Harness>(h: &H) {
    let ops = Ops::case(0);
    let s = h.open();
    capped(&ops, &s, "stale", 10);
    draw(&ops, &s, "stale", 1, 2).expect("epoch 2 draws");
    assert_eq!(
        draw(&ops, &s, "stale", 1, 1),
        Err(ReserveRefused::StaleEpoch),
        "a reserve under an epoch below the stored one is StaleEpoch"
    );
    // Nothing was applied: the remaining headroom is exactly 9.
    draw(&ops, &s, "stale", 9, 2).expect("the stale reserve applied nothing");
    assert_eq!(
        draw(&ops, &s, "stale", 1, 2),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

/// A grant's validity is bounded by SLICE_TTL_MS, and an expired slice's unspent is drawable again.
pub fn valid_until_bounded<H: Harness>(h: &H) {
    let ops = Ops::case(1);
    let s = h.open();
    capped(&ops, &s, "ttl", 5);
    let now = h.now_ms();
    let g = draw(&ops, &s, "ttl", 5, 2).expect("draws the whole window");
    assert!(
        g.valid_until_ms <= now.saturating_add(SLICE_TTL_MS),
        "valid_until_ms {} is past now {now} + SLICE_TTL_MS",
        g.valid_until_ms
    );
    assert_eq!(
        draw(&ops, &s, "ttl", 1, 2),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    h.advance_ms(SLICE_TTL_MS + 1);
    draw(&ops, &s, "ttl", 5, 2).expect("an expired slice's unspent returned to the window");
}

/// The stored epoch survives a restart.
pub fn epoch_survives_restart<H: Harness>(h: &H) {
    let ops = Ops::case(2);
    {
        let s = h.open();
        capped(&ops, &s, "restart", 10);
        draw(&ops, &s, "restart", 1, 3).expect("epoch 3 draws");
    }
    let s = h.open();
    assert_eq!(
        draw(&ops, &s, "restart", 1, 2),
        Err(ReserveRefused::StaleEpoch),
        "the epoch was lost on restart"
    );
}

/// A release of all a slice's unspent under a stale epoch applies once, a repeat returns 0, and the
/// slice's expiry after the release returns nothing more.
pub fn stale_release_exactly_once<H: Harness>(h: &H) {
    let ops = Ops::case(3);
    let s = h.open();
    capped(&ops, &s, "release", 10);
    capped(&ops, &s, "release-fence", 1);
    let g = draw(&ops, &s, "release", 4, 5).expect("epoch 5 draws");
    // The fleet moves on to epoch 6 (a draw elsewhere advances the store's epoch).
    draw(&ops, &s, "release-fence", 1, 6).expect("epoch 6 draws");
    let back = release(&ops, &s, 5, g.slice_id, 4).expect("a release is never refused");
    assert_eq!(back, 4, "the release applies, whatever the epoch");
    let again = release(&ops, &s, 6, g.slice_id, 4).expect("a repeat is answered");
    assert_eq!(again, 0, "a slice with nothing left returns nothing");
    if g.valid_until_ms != u64::MAX {
        h.advance_ms(SLICE_TTL_MS + 1);
    }
    // Drawn 4, returned 4: all 10 of the headroom, and expiry added nothing to that.
    draw(&ops, &s, "release", 10, 6).expect("the returned 4 are drawable");
    assert_eq!(
        draw(&ops, &s, "release", 1, 6),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "expiry returned the released slice again"
    );
}

/// Every case a store a fleet shares runs, in order, over ONE durable state: the epochs the cases
/// present only rise from one case to the next (2, 2, 3, then 5 and 6), so each case also stands
/// alone on a fresh state.
pub fn fleet_store<H: Harness>(h: &H) {
    stale_epoch_refused(h);
    valid_until_bounded(h);
    epoch_survives_restart(h);
    stale_release_exactly_once(h);
}

/// A node-local store's single-node rule (one constant epoch, slices that never expire) and the
/// release rule every store follows.
pub fn single_node_store<H: Harness>(h: &H) {
    let ops = Ops::case(4);
    let s = h.open();
    capped(&ops, &s, "local", 10);
    let g = draw(&ops, &s, "local", 1, 2).expect("draws");
    assert_eq!(
        g.valid_until_ms,
        u64::MAX,
        "a single-node slice never expires"
    );
    draw(&ops, &s, "local", 1, 1).expect("a single-node store never answers StaleEpoch");
    stale_release_exactly_once(h);
}
