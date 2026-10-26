//! Tests for `kernel.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The fee an apply carries reaches the head, and the snapshot a reader already pinned is
/// unmoved.
///
/// The two halves of the append, asserted together because either alone is a half-truth. A
/// holder that took the new fee but let its existing readers see it would bill a request on
/// rates it was never admitted under; a holder that left its readers alone by never taking the
/// new fee at all would pass the second assertion and be the boot-bound card this replaced. The
/// fee is read as the card's own unit price for its flat line, which is where a configured fee
/// ends up.
#[test]
fn an_apply_moves_the_head_and_leaves_a_pinned_reader_on_the_snapshot_it_took() {
    let holder = RootHistory::default();
    assert!(
        holder.pin().is_none(),
        "a holder that has heard no apply prices nothing"
    );

    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    let admitted = holder.pin().expect("the first apply put an entry in place");
    assert_eq!(
        fee_at(&admitted, 1_000),
        30_000_000,
        "the first apply's fee did not reach the entry a reader resolves to"
    );

    // The apply a request in flight must not feel.
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    assert_eq!(
        fee_at(&admitted, 5_000),
        30_000_000,
        "a reader that pinned before the apply was repriced by it, at every instant of its life"
    );
    let next = holder
        .pin()
        .expect("the second apply put an entry in place");
    assert_eq!(
        fee_at(&next, 5_000),
        110_000_000,
        "the apply did not reach the next admission's snapshot"
    );
}

/// The flat fee the entry in force at `at` names. The one reading the tests below compare cards
/// by, so that a comparison is a lookup rather than a field peek.
fn fee_at(pinned: &PinnedHistory, at: u64) -> u128 {
    pinned
        .view()
        .card_at(at)
        .expect("an entry covers the instant")
        .1
        .fee_unit_price_nanos()
}

/// **APPEND, NEVER REWRITE.** A reload puts a SECOND entry on the history and leaves the first
/// exactly as it was written.
///
/// This is the invariant the whole design rests on and it is the one the previous holder broke
/// by construction: it stored one card and a second apply overwrote it, so every posting the
/// node had ever taken silently re-priced at the new figure on the next read. Three assertions,
/// because two of them alone would pass on a holder that replaced: the count MOVES, the first
/// entry's card is UNCHANGED, and the first entry's number is unchanged too — a history that
/// renumbered would break every invoice that named a snapshot.
#[test]
fn a_reload_appends_and_never_rewrites_the_entry_before_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(29), 3_000);

    assert_eq!(
        holder.len(),
        3,
        "three applies left fewer than three entries, so one of them overwrote another"
    );

    let head = holder.pin().expect("three applies put a head in place");
    let view = head.view();
    let entries = view.entries();
    assert_eq!(
        entries[0].card().fee_unit_price_nanos(),
        30_000_000,
        "the entry the first apply wrote was rewritten by a later one"
    );
    assert_eq!(
        entries[0].seq(),
        busbar_kernel_ledger::cost::HistorySeq(0),
        "the first entry was renumbered, which unmakes every invoice that named a snapshot"
    );
    assert_eq!(entries[1].card().fee_unit_price_nanos(), 110_000_000);
    assert_eq!(entries[2].card().fee_unit_price_nanos(), 290_000_000);
}

/// **AN ENTRY PRICES WHAT HAPPENS AFTER IT.** An instant before a reload resolves to the entry
/// that was in force then, and an instant after it resolves to the new one — on the same
/// snapshot, read at the same moment.
///
/// The heart of the model stated as one lookup: the answer depends on WHEN the unit arrived and
/// not on when the question is asked. A holder that replaced its card answers the same figure
/// for both instants, which is exactly the recorded 1.5.5 behaviour this replaces.
#[test]
fn an_instant_before_a_reload_resolves_to_the_entry_that_was_in_force_then() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);

    let head = holder.pin().expect("two applies put a head in place");
    assert_eq!(
        fee_at(&head, 1_500),
        30_000_000,
        "a unit that arrived before the reload was re-priced at the card that replaced it"
    );
    assert_eq!(
        fee_at(&head, 2_500),
        110_000_000,
        "a unit that arrived after the reload was priced at the card it superseded"
    );
}

/// **THE FIRST ENTRY COVERS EVERY INSTANT BEFORE IT**, because a hole is a refusal and a request
/// the node dated a millisecond before its own boot is not a free request.
///
/// A first entry effective from the boot instant would leave instant zero — and every legacy row
/// carrying nothing finer than a UTC day — resolving to nothing, which the lookup reports as
/// unpriceable and the settlement posts as no row at all.
#[test]
fn the_first_entry_covers_every_instant_before_the_boot_that_wrote_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 9_000_000);
    let head = holder.pin().expect("the apply put an entry in place");
    assert_eq!(
        fee_at(&head, 0),
        30_000_000,
        "instant zero fell in a hole, so a pre-boot row prices at nothing"
    );
    assert_eq!(fee_at(&head, 8_999_999), 30_000_000);
}

/// **THE CARD A CONFIG APPLY BUILDS CARRIES THE FEE IT WAS CONFIGURED WITH, AT THE ONE SCALE.**
///
/// This stands where `the_card_an_apply_builds_prices_the_currency_the_node_reads_it_in` stood.
/// That case caught a card built in one denomination and read in another — the lookup would report
/// `CurrencyNotPriced`, which a caller that mapped errors to zero would post as a free request.
/// #66 (`BUSBAR-1.6.0.md:528`) removes the denomination, so the mismatch cannot be CONSTRUCTED
/// rather than merely refused; what is left to assert is that the configured figure reaches the
/// card unmoved and at the one scale.
#[test]
fn the_card_an_apply_builds_carries_its_configured_fee_at_the_one_scale() {
    let holder = RootHistory::default();
    holder.apply(
        super::card_from_config(
            std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
            7,
            true,
        ),
        1_000,
    );
    let head = holder.pin().expect("the apply put an entry in place");
    let view = head.view();
    let (_, card) = view.card_at(1_000).expect("an entry covers it");
    assert_eq!(card.fee(), 7, "the configured fee reached the card unmoved");
    assert_eq!(
        card.fee_unit_price_nanos(),
        7 * busbar_kernel_ledger::cost::NANOS_PER_CENT,
        "the fee lifts to nano-units at the one scale and no other"
    );
}

/// **EVERY DATED CARD PRICES THE OPEN CLASSES THE LIVE ONE DOES** (item 123 × Q14, P2-rootfollow).
///
/// A rerank lane prices `search_units` at 5 µ/unit, then an edit mid-window moves it to 3 µ/unit.
/// 1,000,000 units were earned under the first card and 2,000,000 under the second. The history
/// entry each era resolves to is built by the SAME builder a rate apply uses, so the older era's
/// card carries the open-class cell: 5,000,000 + 6,000,000 = 11,000,000 micro (1,100 minor), and
/// nothing refuses. Before the builder carried `units`, the older era's card had no
/// `search_units` cell and the whole read REFUSED with `ClassUnpriced`.
#[test]
fn a_card_edit_mid_window_prices_an_open_class_in_both_eras_and_refuses_neither() {
    let zero = busbar_contract::billing::RawTierRates {
        input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        output: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
    };
    let lanes = [("rerank".to_string(), zero)];
    let era = |nanos: u64| [("rerank".to_string(), "search_units".to_string(), nanos)];
    let (before, after) = (era(5_000), era(3_000));
    let no_fees = busbar_kernel::config::PlaneFeesMap::new();
    let raw = |units| busbar_kernel::rate_apply::RawRates {
        lanes: &lanes,
        units,
        flat_minor: 0,
        present: true,
        plane_fees: &no_fees,
    };

    let holder = RootHistory::default();
    holder.apply(super::card_from_raw(&raw(&before)), 1_000);
    holder.apply(super::card_from_raw(&raw(&after)), 2_000);
    let history = holder.history().expect("two applies are a history");
    let live = super::card_from_raw(&raw(&after));

    let earned_before = std::collections::BTreeMap::from([("search_units".to_string(), 1_000_000)]);
    let earned_after = std::collections::BTreeMap::from([("search_units".to_string(), 2_000_000)]);
    let priced = busbar_kernel_ledger::usage::price_dated(
        [
            ("rerank", 0, &earned_before),
            ("rerank", 2_000, &earned_after),
        ],
        [],
        0,
        &live,
        Some(busbar_kernel_ledger::usage::DatedHistory::of(
            &history, 3_000,
        )),
    )
    .expect("an open class the older era's card priced must price, not refuse");
    assert_eq!(
        priced.micros(),
        11_000_000,
        "each era at the open-class rate in force when it was earned"
    );
}

/// **A PLANE'S FEES ARE DATED WITH THE CARD** (#47 × Q14, OWNER RULING Q32). Plane `tp` charges 3
/// minor units a request, then an edit mid-window moves it to 7. 2 requests were earned under the
/// first card and 1 under the second: 2 × 3 + 1 × 7 = 13 minor units — each era at the fees in force
/// when it was earned, because every dated entry is built with the plane fees its apply carried.
#[test]
fn a_fee_edit_mid_window_prices_each_era_at_the_plane_fee_in_force() {
    use busbar_kernel_ledger::cost::{plane_fee_lane, PlaneFees, PER_REQUEST};
    let fees = |per_request| {
        let f = PlaneFees {
            per_request,
            per_session: 0,
        };
        busbar_kernel::config::PlaneFeesMap::from([("tp".to_string(), f)])
    };
    let (before, after) = (fees(3), fees(7));
    let raw = |plane_fees| busbar_kernel::rate_apply::RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 5,
        present: false,
        plane_fees,
    };
    let holder = RootHistory::default();
    holder.apply(super::card_from_raw(&raw(&before)), 1_000);
    holder.apply(super::card_from_raw(&raw(&after)), 2_000);
    let history = holder.history().expect("two applies are a history");
    let live = super::card_from_raw(&raw(&after));
    let lane = plane_fee_lane("tp");
    let two = std::collections::BTreeMap::from([(PER_REQUEST.to_string(), 2)]);
    let one = std::collections::BTreeMap::from([(PER_REQUEST.to_string(), 1)]);
    let priced = busbar_kernel_ledger::usage::price_dated(
        [(lane.as_str(), 0, &two), (lane.as_str(), 2_000, &one)],
        [],
        0,
        &live,
        Some(busbar_kernel_ledger::usage::DatedHistory::of(
            &history, 3_000,
        )),
    )
    .expect("a plane's fee units price");
    assert_eq!(priced.minor(), 13, "each era at the plane fee in force");
}

/// A unit no plane on this node composed is not sealed as an administrative read.
///
/// Both audit doors are asked, because both used to answer with the admin plane's word for a
/// verb that did not resolve: a plane unit refused at the root came out of the record as an
/// operator reading a page. The assertion is written as an inequality against that word as well
/// as an equality on the right one, because what matters is not which class replaced it but
/// that no unit of another plane wears the admin plane's.
#[cfg(feature = "root-admin")]
#[test]
fn a_unit_this_root_did_not_compose_is_not_sealed_as_an_admin_read() {
    let units = ProductionUnits::admin_only(
        std::sync::Arc::new(crate::root::units_admin::RefusingDispatch),
        crate::root::units_admin::open_door(),
    );
    let seal = busbar_kernel::test_support::tokens::seal();
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::ids::UnitKey::new(9),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    assert!(
        !units.is_admin(&ctx),
        "the fixture must be a unit the admin plane never claimed"
    );
    let admin_read = busbar_contract::ids::OpClassId::new("admin_read");

    let token: Pass<Audit> = busbar_kernel::test_support::tokens::pass();
    let refused = units
        .audit_refused(
            &token,
            &ctx,
            &Refusal::new(busbar_contract::caps::ReasonCode::NoDestination),
        )
        .into_result(&seal)
        .expect("the door seals a record for a unit it did not compose");
    assert_ne!(refused.op_class, admin_read);
    assert_eq!(
        refused.op_class,
        busbar_contract::ids::OpClassId::new(OP_UNCLAIMED)
    );
    assert_eq!(refused.finish, busbar_contract::FinishClass::Error);

    let token: Pass<Audit> = busbar_kernel::test_support::tokens::pass();
    let ended = units
        .audit(&token, &ctx, &Outcome::Completed)
        .into_result(&seal)
        .expect("the other door seals one too");
    assert_ne!(ended.op_class, admin_read);
    assert_eq!(
        ended.op_class,
        busbar_contract::ids::OpClassId::new(OP_UNCLAIMED)
    );
    assert_eq!(ended.finish, busbar_contract::FinishClass::Complete);
}

/// The arrival door is the admission unit's, and the hold it opens is the caller's — the point of
/// the arrival hold is that even a refusal is an event with a cell of its own to settle.
#[test]
fn the_arrival_door_opens_the_callers_hold() {
    let kernel = new_kernel();
    let door = AdmissionDoor;
    let hold = busbar_kernel::inflight::arrival_hold(
        &kernel,
        &door,
        PrincipalId::new("k-7"),
        kernel.next_call(),
    );
    assert_eq!(hold.principal(), &PrincipalId::new("k-7"));
}

/// The whole assembly, end to end: a kernel, a durability stack that opened nothing, the
/// configured breaker ladders and a scope policy that permits only what it was told about —
/// composed into the one type the loop reaches a unit through.
///
/// Every argument is a value configuration decided. That is the shape that makes it impossible
/// to build these units and forget one: there is no constructor that fills a policy in from a
/// default.
#[test]
fn the_units_assemble_from_values_configuration_decided() {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let kernel = new_kernel();
    let units = ProductionUnits::new(
        &kernel,
        durability,
        crate::root::adapters::BreakerPolicy::new(),
        #[cfg(feature = "root-admin")]
        crate::root::units_admin::AdminBinding::new(
            std::sync::Arc::new(crate::root::units_admin::RefusingDispatch),
            crate::root::units_admin::open_door(),
        ),
        None,
    );

    // Nothing is in flight before anything arrives, which is the machine-checkable half of
    // "an entry that outlived its unit would be a leak per request".
    #[cfg(feature = "root-admin")]
    assert!(units.admin.units.is_empty());

    // The journal opened nothing: the safe end of a choice that had an unsafe end, checkable here
    // rather than at the first request.
    let durability = units.durability.lock().expect("durability lock");
    assert!(!durability.on_disk());
}

/// A store that writes down every primitive it is asked for, so a test can say WHICH store a call
/// landed on rather than inferring it from an `Ok`.
#[cfg(feature = "root-admin")]
#[derive(Default)]
struct ReachedStore(Mutex<Vec<String>>);

#[cfg(feature = "root-admin")]
impl ReachedStore {
    fn note(&self, line: String) {
        self.0.lock().expect("the log lock").push(line);
    }

    fn reached(&self) -> Vec<String> {
        self.0.lock().expect("the log lock").clone()
    }
}

#[cfg(feature = "root-admin")]
impl busbar_contract::verb_store::Store for ReachedStore {
    fn chain_break(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        self.note("chain_break".to_string());
        Ok(())
    }

    fn store_restore(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        backup_ref: &str,
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        self.note(format!("store_restore {backup_ref}"));
        Ok(())
    }

    fn reseal_epoch_floor(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        self.note("reseal_epoch_floor".to_string());
        Ok(())
    }

    fn replay_new_verb(
        &self,
        key: &(String, String),
    ) -> Result<Option<Vec<u8>>, busbar_contract::verb_store::StoreError> {
        self.note(format!("replay_new_verb {} {}", key.0, key.1));
        Ok(None)
    }

    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        _response: &[u8],
    ) -> Result<(), busbar_contract::verb_store::StoreError> {
        self.note(format!("commit_new_verb_replay {} {}", key.0, key.1));
        Ok(())
    }
}

/// ROW 113: THE ADMIN UNITS OVER A BOOK REACH THAT BOOK'S STORE, for every recovery primitive and
/// the replay slot.
///
/// `ProductionUnits::admin_over_book` is the one composition `main` serves the admin listener
/// through, and the `route` step hands `units.store` to the verbs unit. So the store the units hold
/// IS the store every disaster-recovery verb lands on. The book here carries a store that writes
/// down what reached it; each primitive is driven through the units' handle and must appear on that
/// store, in order, with the backup the operator named. RED: units that hold no store (the refusing
/// stand-in this row deleted) fail the `expect`; units that hold any other store leave this one's
/// log empty.
#[cfg(feature = "root-admin")]
#[test]
fn the_admin_units_over_a_book_reach_that_books_store_for_every_recovery_verb() {
    let configured = Arc::new(ReachedStore::default());
    let mut book = crate::root::durability::node_book();
    book.verb_store = Some(Arc::clone(&configured) as _);
    let units = ProductionUnits::admin_over_book(
        Arc::new(crate::root::units_admin::RefusingDispatch),
        crate::root::units_admin::open_door(),
        &book,
    );
    let store = units
        .store
        .as_ref()
        .expect("units over a book with a configured store hold a store");

    let key = (
        "idem-row-113".to_string(),
        "POST /api/v1/admin/keys".to_string(),
    );
    store
        .chain_break(&units.admin_token)
        .expect("chain_break applies");
    store
        .store_restore(&units.admin_token, "nightly")
        .expect("store_restore applies");
    store
        .reseal_epoch_floor(&units.admin_token)
        .expect("reseal_epoch_floor applies");
    store
        .commit_new_verb_replay(&key, b"first answer")
        .expect("the replay slot commits");
    store.replay_new_verb(&key).expect("the replay slot reads");

    assert_eq!(
        configured.reached(),
        vec![
            "chain_break".to_string(),
            "store_restore nightly".to_string(),
            "reseal_epoch_floor".to_string(),
            "commit_new_verb_replay idem-row-113 POST /api/v1/admin/keys".to_string(),
            "replay_new_verb idem-row-113 POST /api/v1/admin/keys".to_string(),
        ],
        "every recovery primitive and the replay slot landed on the book's configured store"
    );
}

/// The interner is idempotent, which is what makes "leaked exactly once" a property of the
/// type rather than of the caller's discipline.
#[test]
fn the_interner_leaks_a_repeated_key_once() {
    let mut registration = new_registration();
    let first = registration
        .key("lane-a")
        .expect("an unfrozen image interns a key");
    let second = registration
        .key("lane-a")
        .expect("a repeated key is the same key");
    assert!(std::ptr::eq(first, second));
    assert_eq!(registration.len(), 1);
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE USAGE READ'S DATED-HISTORY SEAM (DECISION #79)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The holder hands a reader the WHOLE history, and hands a node that has resolved nothing
/// NOTHING.
///
/// [`RootHistory::pin`] fixes the head for a request's whole life; a ledger READ wants the
/// entries and its own choice of snapshot, so it takes the `Arc` instead. The absent arm is the
/// half worth asserting: a node that has read no configuration must answer "no history" rather
/// than an empty one, because an empty history prices every instant at nothing and nothing is a
/// price.
#[test]
fn the_holder_hands_a_reader_the_whole_history_and_an_unresolved_node_none() {
    let holder = RootHistory::default();
    assert!(
        holder.history().is_none(),
        "a node that has resolved no configuration has no history to hand over"
    );

    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    let history = holder.history().expect("two applies are a history");
    assert_eq!(
        history.len(),
        2,
        "the reader sees every entry, not just the head"
    );
    assert_eq!(
        history.head(),
        Some(busbar_kernel_ledger::cost::HistorySeq(1)),
        "and the numbers are the holder's own, so a snapshot names the same entry twice"
    );
}

/// The read the usage view asks through answers with the PROCESS history and nothing of its own:
/// the date half's `history` (what `busbar_kernel::rate_apply::dated_history` hands the admin
/// usage read and the budget book) is the holder's.
///
/// A delegation is the whole implementation, so the assertion is that the two readings agree —
/// an implementor that built its own history would answer a different length the moment the
/// process's moved, and an invoice would be priced against a history no apply ever reached.
#[test]
fn the_usage_read_answers_with_the_process_history() {
    use busbar_kernel::rate_apply::RateEpoch as _;
    assert_eq!(
        CardRepricer.history().map(|h| h.len()),
        ROOT_CARD.history().map(|h| h.len()),
        "the read answers from a history the process never resolved"
    );
    assert_eq!(
        CardRepricer.history().and_then(|h| h.head()),
        ROOT_CARD.history().and_then(|h| h.head()),
        "the read and the holder disagree about which entry is the head"
    );
}

/// The module names `[package.metadata.busbar.root-units]` lists, in manifest order.
fn root_unit_modules(manifest: &str) -> Vec<String> {
    let mut in_table = false;
    let mut modules = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[package.metadata.busbar.root-units]";
            continue;
        }
        if let (true, Some((_, module))) = (in_table, code.split_once('=')) {
            modules.push(module.trim().trim_matches('"').to_string());
        }
    }
    assert!(!modules.is_empty(), "the manifest lists no root unit");
    modules
}

// ---------------------------------------------------------------------------------------------
// The dated history, journalled (#79, OWNER RULING Q14 "date everything")
// ---------------------------------------------------------------------------------------------

/// The flat lane the history tests price.
const FLAT_LANE: &str = "gpt";
/// The plane whose own card (#47) the history tests price. Any plane key reads the same: the card,
/// its presence key and its fee lane are keyed on the string, never on which plane it is.
const PLANE: &str = "planex";
/// That plane's own lane (#47): its card prices it, at twice the flat card's rate.
const PLANE_LANE: &str = "planex\u{1f}search";

/// When the history tests' events land, in wall-clock milliseconds.
const BOOT_A: u64 = 1_000;
const EARNED_A: u64 = 10_000;
const APPLIED_B: u64 = 20_000;
const EARNED_B: u64 = 30_000;
const REBOOT: u64 = 40_000;
const REBOOT_CHANGED: u64 = 50_000;

fn tiers(input: f64) -> busbar_contract::billing::RawTierRates {
    busbar_contract::billing::RawTierRates {
        input: busbar_kernel_ledger::cost::representable_nano_rate(input),
        output: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
    }
}

/// The deployment's lanes at one price: [`FLAT_LANE`] at `price` micro-units an input token, and
/// the [`PLANE`] plane's card (its presence key and [`PLANE_LANE`]) at twice that.
fn lanes_at(price: f64) -> Vec<(String, busbar_contract::billing::RawTierRates)> {
    vec![
        (FLAT_LANE.to_string(), tiers(price)),
        (format!("{PLANE}\u{1f}"), tiers(0.0)),
        (PLANE_LANE.to_string(), tiers(2.0 * price)),
    ]
}

fn plane_fees() -> busbar_kernel::config::PlaneFeesMap {
    busbar_kernel::config::PlaneFeesMap::from([(
        PLANE.to_string(),
        busbar_kernel_ledger::cost::PlaneFees {
            per_request: 7,
            per_session: 11,
        },
    )])
}

/// The card the engine resolves at `price` (as [`try_apply_at`] builds it), published on `holder`'s
/// history at `at` with NO record on any journal: the raw [`RootHistory::apply`].
#[cfg(feature = "root-admin")]
fn publish_unjournalled_at(holder: &RootHistory, price: f64, at: u64) {
    let lanes = lanes_at(price);
    let fees = plane_fees();
    holder.apply(
        super::card_from_raw(&busbar_kernel::rate_apply::RawRates {
            lanes: &lanes,
            units: &[("gpt".to_string(), "search_units".to_string(), 2_000)],
            flat_minor: 4,
            present: true,
            plane_fees: &fees,
        }),
        at,
    );
}

/// A book over `dir`, its rate-card holder named: the holder loads nothing (no store is kept), so the
/// book opens on the chain alone.
fn open_book(
    holder: &'static RootHistory,
    dir: &std::path::Path,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    let book = crate::root::durability::build_with_cards(
        &crate::root::durability::DurabilityConfig {
            data_dir: Some(dir.to_path_buf()),
        },
        7,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Some(holder),
    )
    .expect("the journal opens");
    Arc::new(Mutex::new(book))
}

/// What a million `input` tokens earned on `lane` at `at` cost, in nano-units: the counts priced by
/// the card `holder`'s history holds in force at `at` (money is counts x the card, MONEY-DESIGN §3).
fn earned(holder: &RootHistory, lane: &str, at: u64) -> u64 {
    let price = holder
        .history()
        .expect("a history")
        .current()
        .card_at(at)
        .and_then(|(_, card)| card.lane_rates(lane).map(|r| r.nanos_per_unit("input")))
        .expect("a card prices the lane");
    1_000_000 * price
}

/// What a million tokens earned at A and a million at B come to on each lane, at `holder`'s history.
fn figures(holder: &RootHistory) -> (u64, u64) {
    (
        earned(holder, FLAT_LANE, EARNED_A) + earned(holder, FLAT_LANE, EARNED_B),
        earned(holder, PLANE_LANE, EARNED_A) + earned(holder, PLANE_LANE, EARNED_B),
    )
}

/// `GET /admin/usage`'s dated derivation of one metering row of `input` tokens on [`FLAT_LANE`]
/// dated `priced_from_ms`, through `holder`'s history — the history the read is handed
/// (the rate dater hands the process holder's).
fn usage_row_micros(holder: &RootHistory, priced_from_ms: u64, input: u64) -> i64 {
    let history = holder.history().expect("a resolved history");
    let live = history
        .current()
        .card_at(u64::MAX)
        .map(|(_, card)| card.clone())
        .expect("a head card");
    let cost = busbar_kernel::cost::CostModel::resolve_parts(
        Some(&std::collections::BTreeMap::from([(
            FLAT_LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 1.0,
                ..Default::default()
            },
        )])),
        0,
        &std::collections::BTreeMap::new(),
    );
    use busbar_core_admin::v1::service::read_path_money as invoice;
    invoice::derive_spend_micros_row_at_card(
        &history.current(),
        priced_from_ms,
        &live,
        &cost,
        FLAT_LANE,
        &invoice::UsageBreakdown {
            tokens_input: input,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
            requests: 0,
            spend_micros: 0,
            classes: Default::default(),
        },
    )
    .expect("the row prices")
}

/// A store that takes nothing: a memory-buffered journal over it refuses every append.
struct RefusingShipper;

impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for RefusingShipper {
    fn ship(
        &mut self,
        _records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        Err(busbar_kernel_wal::ShipError::Unavailable(
            "the store is not answering".into(),
        ))
    }
}

/// The flat lane's input price in force at `at` on `holder`'s history.
fn flat_price_at(holder: &RootHistory, at: u64) -> Option<u64> {
    holder
        .history()
        .expect("a history")
        .current()
        .card_at(at)
        .and_then(|(_, card)| {
            card.lane_rates(FLAT_LANE)
                .map(|r| r.nanos_per_unit("input"))
        })
}

/// A store whose answer the test flips: refusing, a memory-buffered journal over it retains every
/// batch and re-offers it on the next append; answering, the retained batch lands.
struct SwitchShipper(Arc<std::sync::atomic::AtomicBool>);

impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for SwitchShipper {
    fn ship(
        &mut self,
        _records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(busbar_kernel_wal::ShipError::Unavailable(
                "the store is not answering".into(),
            ));
        }
        Ok(())
    }
}

/// The flat lane's input price in force at `at` on `history`.
fn flat_price_on(history: &busbar_kernel_ledger::cost::History, at: u64) -> Option<u64> {
    history.current().card_at(at).and_then(|(_, card)| {
        card.lane_rates(FLAT_LANE)
            .map(|r| r.nanos_per_unit("input"))
    })
}

/// A disk the test can break: while `failing`, every write, sync and resize on a segment fails (the
/// segment poisons) and no fresh segment opens, so a poisoned log cannot roll.
struct BreakableDisk {
    failing: Arc<std::sync::atomic::AtomicBool>,
    highest: Option<u64>,
}

struct BreakableSegment {
    inner: busbar_kernel_wal::MemorySegment,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

impl BreakableSegment {
    fn check(&self) -> std::io::Result<()> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("the disk is gone"));
        }
        Ok(())
    }
}

impl busbar_kernel_wal::SegmentBackend for BreakableSegment {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.check()?;
        self.inner.write_all_at(offset, bytes)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.check()?;
        self.inner.sync()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read_at(offset, buf)
    }
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.check()?;
        self.inner.set_len(len)
    }
}

impl busbar_kernel_wal::SegmentFactory for BreakableDisk {
    fn open(&mut self, index: u64) -> std::io::Result<Box<dyn busbar_kernel_wal::SegmentBackend>> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("no segment opens on a gone disk"));
        }
        self.highest = Some(self.highest.map_or(index, |h| h.max(index)));
        Ok(Box::new(BreakableSegment {
            inner: busbar_kernel_wal::MemorySegment::new(),
            failing: Arc::clone(&self.failing),
        }))
    }
    fn highest_index(&self) -> std::io::Result<Option<u64>> {
        Ok(self.highest)
    }
    // This disk keeps no segment once it has handed it to the log (every `open` is a fresh
    // memory segment), so it holds nothing earlier a reader could reach — and the test never
    // replays it.
    fn existing(
        &self,
        _index: u64,
    ) -> std::io::Result<Option<Box<dyn busbar_kernel_wal::SegmentBackend>>> {
        Ok(None)
    }
    fn is_durable(&self) -> bool {
        true
    }
    fn segment_file(&self, _index: u64) -> Option<std::path::PathBuf> {
        None
    }
    fn quarantine(
        &mut self,
        _index: u64,
        _offset: u64,
        _unix_ms: u64,
        _bytes: &[u8],
    ) -> std::io::Result<Option<std::path::PathBuf>> {
        Ok(None)
    }
}

/// The book's chain swapped for a memory-buffered one over a store the test flips (refusing at
/// first, as `refusing` says), answering the flag.
fn swap_to_switchable_store(
    book: &Arc<Mutex<crate::root::durability::Durability>>,
    refusing: bool,
) -> Arc<std::sync::atomic::AtomicBool> {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(refusing));
    book.lock().expect("the book").journal = busbar_kernel_wal::Journal::memory_buffered_to(
        7,
        Box::new(SwitchShipper(Arc::clone(&flag))),
        busbar_kernel::store::now_ms,
    );
    flag
}

/// **AN APPLIED CARD ROUND-TRIPS THE JOURNAL AS THE SAME CARD, EVERY PLANE INCLUDED** (#47): the
/// flat lane's four classes and its open class, the plane's own lane, an unconfigured lane on each
/// (refused, #42), and each plane's fees read back identically off the rebuilt card.
#[test]
fn an_applied_card_round_trips_the_journal_as_the_same_card_on_every_plane() {
    let lanes = lanes_at(3.0);
    let fees = plane_fees();
    let units = [("gpt".to_string(), "search_units".to_string(), 2_000)];
    let raw = busbar_kernel::rate_apply::RawRates {
        lanes: &lanes,
        units: &units,
        flat_minor: 4,
        present: true,
        plane_fees: &fees,
    };
    let card = super::card_from_raw(&raw);
    let applied = super::CardApplied {
        effective_from: APPLIED_B,
        appended_at: APPLIED_B,
        policy_epoch: 3,
        form: super::CardForm::of(&raw, &card),
    };
    let read = super::CardApplied::from_body(&applied.body()).expect("the body reads back");
    assert_eq!(read, applied);
    let rebuilt = read.form.card();
    let fee_lane = busbar_kernel_ledger::cost::plane_fee_lane(PLANE);
    for lane in [
        FLAT_LANE,
        PLANE_LANE,
        "other",
        "planex\u{1f}other",
        fee_lane.as_str(),
    ] {
        assert_eq!(
            rebuilt.lane_unpriced(lane),
            card.lane_unpriced(lane),
            "{lane}"
        );
        for class in [
            "input",
            "output",
            "cache_read",
            "cache_write",
            "search_units",
        ] {
            let of = |c: &busbar_kernel_ledger::cost::RateCard| {
                c.lane_rates(lane)
                    .map(|r| (r.nanos_per_unit(class), r.class_priced(class)))
            };
            assert_eq!(of(&rebuilt), of(&card), "{lane} {class}");
        }
        for class in ["per_request", "per_session"] {
            assert_eq!(
                rebuilt.plane_lane(lane).0.fee_of(class),
                card.plane_lane(lane).0.fee_of(class),
                "{lane} {class}"
            );
        }
    }
    assert_eq!(rebuilt.fee(), card.fee());
    assert_eq!(rebuilt.pricing_enabled(), card.pricing_enabled());
    assert!(
        super::CardApplied::from_body(b"not a card").is_none(),
        "another Policy record is not read as a card"
    );

    // An ABSENT card round-trips absent, fee and plane fees included.
    let absent = busbar_kernel::rate_apply::RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 9,
        present: false,
        plane_fees: &fees,
    };
    let card = super::card_from_raw(&absent);
    let rebuilt = super::CardForm::of(&absent, &card).card();
    assert!(!rebuilt.pricing_enabled());
    assert_eq!(rebuilt.fee(), 9);
    assert_eq!(
        rebuilt.plane_lane(&fee_lane).0.fee_of("per_session"),
        Some(11)
    );
}

/// The effect half of `amend_rate_history`, as `amend_rate_history_effect` runs it: [`FLAT_LANE`]
/// `input` corrected to `nanos` over `window`, signed at `signed_at`, its `v3` record sealed onto
/// `book` (ahead of the append) with the base `rebase` makes of the one the append resolved. Every
/// honest record is `rebase` = the identity.
#[cfg(feature = "root-admin")]
fn seal_correction(
    holder: &RootHistory,
    book: &Arc<Mutex<crate::root::durability::Durability>>,
    window: (u64, u64),
    signed_at: u64,
    nanos: u64,
    rebase: impl FnOnce(super::CorrectionBase) -> super::CorrectionBase,
) -> busbar_kernel_ledger::cost::HistorySeq {
    use busbar_contract::caps::DurableWrite;
    let journal = crate::root::units_admin::AmendmentJournal::new(
        Arc::clone(book),
        busbar_kernel::test_support::tokens::grant::<DurableWrite>(),
    );
    holder
        .amend(
            &super::Correction {
                effective_from: window.0,
                effective_until: Some(window.1),
                appended_at: signed_at,
                author: busbar_kernel_ledger::cost::Author::Amend {
                    reason_hash: [9; 32],
                },
                cells: vec![(
                    busbar_kernel_ledger::cost::LaneClass::new(FLAT_LANE, "input"),
                    nanos,
                )],
                fee: None,
            },
            |card, base| {
                journal.record(
                    &crate::root::units_admin::AmendmentRecord {
                        effective_from: window.0,
                        effective_until: Some(window.1),
                        amended_at_ms: signed_at,
                        sealed_over: Some(rebase(base)),
                        sealed_fee: card.fee(),
                        rates: vec![(FLAT_LANE.to_string(), "input".to_string(), Some(nanos))],
                        operator_fingerprint: "op".to_string(),
                        reason_hash: [9; 32],
                        principal: "admin".to_string(),
                        dual_control: "single".to_string(),
                        signed_payload: b"signed".to_vec(),
                        signature: "00".to_string(),
                    },
                    signed_at / 1_000,
                )
            },
        )
        .expect("a resolved history takes a correction")
}

/// APPLYING A CONFIGURATION REGISTERS EVERY CLASS A UNIT MAY REPORT: the reserved four and each
/// open class a lane's `units:` names resolve afterwards by lookup, and a class nobody configured or
/// declared does not.
#[test]
fn applying_rates_registers_the_classes_a_unit_may_report() {
    let fees = plane_fees();
    let lanes = lanes_at(1.0);
    busbar_kernel::rate_apply::RateApply::rates_applied(
        &super::CardRepricer,
        &busbar_kernel::rate_apply::RawRates {
            lanes: &lanes,
            units: &[(
                "gpt".to_string(),
                "configured_open_units".to_string(),
                2_000,
            )],
            flat_minor: 0,
            present: false,
            plane_fees: &fees,
        },
    );
    for class in busbar_contract::records::RESERVED_UNITS {
        assert!(
            busbar_kernel::Registration::resolve(class).is_some(),
            "{class}"
        );
    }
    assert!(busbar_kernel::Registration::resolve("configured_open_units").is_some());
    assert_eq!(
        busbar_kernel::Registration::resolve("a_class_nobody_declared_or_configured"),
        None
    );
}
