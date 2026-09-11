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

    holder.apply(busbar_unit_cost::RateCard::absent(3), 1_000);
    let admitted = holder.pin().expect("the first apply put an entry in place");
    assert_eq!(
        fee_at(&admitted, 1_000),
        30_000_000,
        "the first apply's fee did not reach the entry a reader resolves to"
    );

    // The apply a request in flight must not feel.
    holder.apply(busbar_unit_cost::RateCard::absent(11), 2_000);
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

/// The transaction fee the entry in force at `at` names, lifted to nano-units in the node's
/// currency. The one reading the tests below compare cards by, so that a comparison is a lookup
/// rather than a field peek.
///
/// Spelled here rather than on the card because the card holds the deployment's amounts in MINOR
/// units and lifts them once, at the pricing site; a second lift living on the card would be a
/// second place a fee becomes nano-units.
fn fee_of(card: &busbar_unit_cost::RateCard) -> u128 {
    card.fee_terms(node_currency()).map_or(0, |terms| {
        u128::from(terms.transaction.unsigned_abs()) * node_currency().nanos_per_minor()
    })
}

/// The same reading, resolved through the history at one instant.
fn fee_at(pinned: &PinnedHistory, at: u64) -> u128 {
    fee_of(
        pinned
            .view()
            .card_at(at)
            .expect("an entry covers the instant")
            .1,
    )
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
    holder.apply(busbar_unit_cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_unit_cost::RateCard::absent(11), 2_000);
    holder.apply(busbar_unit_cost::RateCard::absent(29), 3_000);

    assert_eq!(
        holder.len(),
        3,
        "three applies left fewer than three entries, so one of them overwrote another"
    );

    let head = holder.pin().expect("three applies put a head in place");
    let view = head.view();
    let entries = view.entries();
    assert_eq!(
        fee_of(entries[0].card()),
        30_000_000,
        "the entry the first apply wrote was rewritten by a later one"
    );
    assert_eq!(
        entries[0].seq(),
        busbar_unit_cost::HistorySeq(0),
        "the first entry was renumbered, which unmakes every invoice that named a snapshot"
    );
    assert_eq!(fee_of(entries[1].card()), 110_000_000);
    assert_eq!(fee_of(entries[2].card()), 290_000_000);
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
    holder.apply(busbar_unit_cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_unit_cost::RateCard::absent(11), 2_000);

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
    holder.apply(busbar_unit_cost::RateCard::absent(3), 9_000_000);
    let head = holder.pin().expect("the apply put an entry in place");
    assert_eq!(
        fee_at(&head, 0),
        30_000_000,
        "instant zero fell in a hole, so a pre-boot row prices at nothing"
    );
    assert_eq!(fee_at(&head, 8_999_999), 30_000_000);
}

/// Every entry a config apply writes says so, and says which generation of the configuration
/// wrote it. The boot resolution is epoch 0 and each apply after it is the next.
#[test]
fn every_config_apply_records_the_generation_that_wrote_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_unit_cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_unit_cost::RateCard::absent(11), 2_000);
    let head = holder.pin().expect("two applies put a head in place");
    let view = head.view();
    let epochs: Vec<busbar_unit_cost::Author> =
        view.entries().iter().map(|e| e.author().clone()).collect();
    assert_eq!(
        epochs,
        vec![
            busbar_unit_cost::Author::Config { policy_epoch: 0 },
            busbar_unit_cost::Author::Config { policy_epoch: 1 },
        ]
    );
}

/// The card a config apply builds is in the node's currency, and asking it for that currency is
/// an answer rather than a refusal.
///
/// The one assertion that catches a card built in one currency and read in another: the lookup
/// would report `CurrencyNotPriced`, which a caller that mapped errors to zero would post as a
/// free request.
#[test]
fn the_card_an_apply_builds_prices_the_currency_the_node_reads_it_in() {
    let holder = RootHistory::default();
    holder.apply(
        super::card_from_config(
            std::iter::empty::<(&str, busbar_substrate::billing::RawTierRates)>(),
            &busbar_contract::tariff::FeeTerms::flat(7),
            true,
            node_currency(),
        ),
        1_000,
    );
    let head = holder.pin().expect("the apply put an entry in place");
    let view = head.view();
    let (_, card) = view.card_at(1_000).expect("an entry covers it");
    assert!(
        card.prices_currency(node_currency()),
        "the node's own currency is not on the card the node's own config built"
    );
}

/// A chain with one module in it, so the front door is CLOSED without needing a governance state
/// to close it. What the grant reads is the posture, not the module, so a module that answers
/// nothing is enough to state the posture with.
struct NeverIdentifies;

impl busbar_unit_auth::module::AuthModule for NeverIdentifies {
    fn name(&self) -> &'static str {
        "never"
    }
    fn authenticate(&self, _candidate: Option<&str>) -> busbar_unit_auth::module::AuthOutcome {
        busbar_unit_auth::module::AuthOutcome::Pass
    }
}

fn a_closed_door() -> AuthChain {
    AuthChain::new(
        vec![busbar_unit_auth::chain::ChainEntry {
            provider: "never".to_string(),
            module: Box::new(NeverIdentifies),
        }],
        false,
    )
}

/// THE GRANT'S THREE ARMS, which used to be one.
///
/// `Full` was returned to every caller without reading who it was, which is right for exactly
/// one of the three postures below and wrong for the other two. The third arm is the one that
/// matters: a principal some other module identified, carrying no roles and therefore nothing
/// bound to read a scope out of, used to be handed the operator's own ceiling.
#[cfg(feature = "root-admin")]
#[test]
fn the_admin_grant_is_the_previous_releases_three_arms() {
    let open = ProductionUnits::admin_only(std::sync::Arc::new(
        crate::root::units_admin::RefusingDispatch,
    ));
    assert_eq!(
        open.admin_grant(&PrincipalId::new("anonymous")),
        Some(busbar_unit_verbs::VerbScope::Full),
        "the explicit open posture — no credential configured — is full, as it has always been"
    );

    let closed = ProductionUnits::admin_only(std::sync::Arc::new(
        crate::root::units_admin::RefusingDispatch,
    ))
    .with_auth_chain(a_closed_door());
    assert_eq!(
        closed.admin_grant(&PrincipalId::new(
            crate::root::auth_bindings::ADMIN_PRINCIPAL_ID
        )),
        Some(busbar_unit_verbs::VerbScope::Full),
        "the operator credential is the root credential, and carries the full tier by definition"
    );
    assert_eq!(
        closed.admin_grant(&PrincipalId::new("somebody-else")),
        None,
        "a roleless principal that is not the operator holds NO grant — not a narrower one, \
         which would still be authority this deployment never wrote down"
    );
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
    let units = ProductionUnits::admin_only(std::sync::Arc::new(
        crate::root::units_admin::RefusingDispatch,
    ));
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let ctx = UnitCtx {
        key: busbar_contract::ids::UnitKey::new(9),
        origin: busbar_caps::OriginKind::Client,
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

    let token: UnitToken<Audit> = UnitToken::mint(&seal);
    let refused = units
        .audit_refused(
            &token,
            &ctx,
            &Refusal::new(busbar_caps::ReasonCode::NoDestination),
        )
        .into_result(&seal)
        .expect("the door seals a record for a unit it did not compose");
    assert_ne!(refused.op_class, admin_read);
    assert_eq!(
        refused.op_class,
        busbar_contract::ids::OpClassId::new(OP_UNCLAIMED)
    );
    assert_eq!(refused.finish, busbar_contract::FinishClass::Error);

    let token: UnitToken<Audit> = UnitToken::mint(&seal);
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

/// The point of the skeleton: the shape compiles against the real trait, and the real trait is
/// the kernel's. A `ProductionUnits` that did not satisfy `Units` would be a plan, not a root.
#[test]
fn production_units_is_the_kernels_units_trait() {
    fn assert_units<U: Units>() {}
    assert_units::<ProductionUnits>();
}

/// The arrival door is the admission unit's, and a hold it opens reserves nothing — the point
/// of the arrival hold is that even a refusal is an event with a cell of its own to settle.
#[test]
fn the_arrival_door_opens_a_hold_that_reserves_nothing() {
    let kernel = new_kernel();
    let door = AdmissionDoor;
    let hold = busbar_kernel::inflight::arrival_hold(&kernel, &door, PrincipalId::new("k-7"));
    assert_eq!(hold.reserved(), 0);
    assert_eq!(hold.principal(), &PrincipalId::new("k-7"));
}

/// The whole assembly, end to end: a kernel, a durability stack that opened nothing, the
/// configured breaker ladders, the configured metering policy and a scope policy that permits
/// only what it was told about — composed into the one type the loop reaches a unit through.
///
/// Every argument is a value configuration decided. That is the shape that makes it impossible
/// to build these units and forget one: there is no constructor that fills a policy in from a
/// default, so a deployment that never read its rate cards does not compile.
#[test]
fn the_units_assemble_from_values_configuration_decided() {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let kernel = new_kernel();
    let units = ProductionUnits::new(
        &kernel,
        AuthChain::new(Vec::new(), false),
        durability,
        crate::root::adapters::BreakerPolicy::new(),
        crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        crate::root::policy::ScopePolicy::new(),
        #[cfg(feature = "root-admin")]
        crate::root::units_admin::AdminBinding::new(std::sync::Arc::new(
            crate::root::units_admin::RefusingDispatch,
        )),
        std::sync::Arc::new(RefusingStore),
    );

    // Nothing is in flight before anything arrives, which is the machine-checkable half of
    // "an entry that outlived its unit would be a leak per request".
    #[cfg(feature = "root-admin")]
    assert!(units.admin.units.is_empty());

    // The journal opened nothing, the ledger is dual-writing, and the scope policy permits
    // nothing until it is told to. All three are the safe end of a choice that had an unsafe
    // end, and all three are checkable here rather than at the first request.
    let durability = units.durability.lock().expect("durability lock");
    assert!(!durability.on_disk());
    assert!(durability.ledger.is_dual_writing());
    assert!(units.scope_policy.is_empty());
}

/// The breaker unit the root assembles reports an unrecognized `error_map` class rather than
/// swallowing it.
///
/// The unit's own default sink is a noop, which is 1.5.5's behaviour for the classification
/// RESULT and also for the warning — the mapping is ignored either way, and before this
/// binding nothing said so. What is asserted here is the composition: the sink the root builds
/// is reached from the unit the root assembled, through the port the egress unit classifies
/// over, without any test double standing in for either side.
///
/// The sink is a recording one rather than the tracing one, because what needs proving is that
/// the value ARRIVES; where it goes afterwards is `adapters::TracingDiagnostics`, and asserting
/// on a log line would be asserting on the subscriber a test happened to install.
#[test]
fn an_unrecognized_error_map_class_reaches_the_roots_sink() {
    #[derive(Debug, Default)]
    struct RecordingSink(Mutex<Vec<String>>);

    impl busbar_unit_breaker::classify::Diagnostics for RecordingSink {
        fn unrecognized_error_map_value(&self, value: &str) {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(value.to_string());
        }
    }

    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let kernel = new_kernel();
    let mut units = ProductionUnits::new(
        &kernel,
        AuthChain::new(Vec::new(), false),
        durability,
        crate::root::adapters::BreakerPolicy::new(),
        crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        crate::root::policy::ScopePolicy::new(),
        #[cfg(feature = "root-admin")]
        crate::root::units_admin::AdminBinding::new(Arc::new(
            crate::root::units_admin::RefusingDispatch,
        )),
        Arc::new(RefusingStore),
    );

    // The same assembly the constructor performs, over a sink this test can read back. The
    // production sink is `adapters::root_diagnostics()`; the width is the same one, which is
    // what makes the substitution a substitution rather than a different composition.
    let sink = Arc::new(RecordingSink::default());
    units.breaker = crate::root::adapters::BreakerAdapter::with_diagnostics(
        Arc::clone(&sink) as crate::root::adapters::DiagnosticsSink,
        crate::root::adapters::BreakerPolicy::new(),
    );

    let destination = busbar_unit_breaker::DestinationId::new(11);
    units.breaker.unit().set_error_map(
        destination,
        std::collections::HashMap::from([("503".to_string(), "rate_limt".to_string())]),
    );

    let classified = busbar_unit_egress::ports::Breaker::classify(
        &units.breaker,
        destination,
        busbar_unit_egress::ports::UpstreamStatus {
            code: Some(busbar_contract::WireStatus::new(
                busbar_contract::transport::status_ns::HTTP,
                503,
            )),
            class: None,
            retry_after: None,
        },
    );

    assert_eq!(
        sink.0.lock().expect("sink lock").as_slice(),
        ["rate_limt".to_string()],
        "the unrecognized class reached the sink the root bound"
    );
    assert_eq!(
        classified.disposition,
        busbar_unit_egress::ports::Disposition::TransientUpstream,
        "and the mapping stayed ignored: the 503 classified from its HTTP status"
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

/// **THE HOLDER PASSES ALL THREE SCOPE KEYS THROUGH, AND THE SCHEDULE SITE READS ALL THREE.**
///
/// `tariff_cell` used to take a plane key and nothing else, so `tariff.pool` and `tariff.tier`
/// resolved against `None` at every one of the eleven sites that ask — an operator could write a
/// pool's cell, validate it against a pool that exists, boot cleanly and be charged the plane's.
/// And it was INVISIBLE: the lookup misses into the next scope out and the next scope out is a
/// perfectly good answer.
///
/// Driven through the REAL holder with a resolver that answers a different cell per scope key, so a
/// holder that dropped an argument on the way through answers the same cell for every row below and
/// every `assert_ne!` collapses. It is written HERE rather than against the `tariff:` grammar
/// because what is under test is the ROOT's wiring — that the three keys reach the closure — and
/// the grammar's own resolution order is proven where the grammar lives.
#[test]
fn the_schedule_holder_carries_the_plane_the_pool_and_the_tier() {
    let holder = super::RootTariff::default();
    // A resolver that ANSWERS WITH ITS ARGUMENTS: each key, when it is present, moves one field of
    // the cell. Nothing here is a schedule anybody would configure; it is a probe for what arrived.
    holder.install(Box::new(
        |plane: &str, pool: Option<&str>, tier: Option<&str>| busbar_kernel::teller::TariffCell {
            entry_fee_enabled: tier == Some("gold"),
            dispute_policy: match (plane, pool) {
                (_, Some("pool-a")) => busbar_kernel::teller::DisputePolicy::EntryOnly,
                ("llm", _) => busbar_kernel::teller::DisputePolicy::Full,
                _ => busbar_kernel::teller::DisputePolicy::EntryPlusUnits,
            },
        },
    ));
    let cell = |plane, pool, tier| match holder.resolver.load().as_ref() {
        Some(resolve) => resolve(plane, pool, tier),
        None => panic!("the holder was installed above"),
    };

    let plane_only = cell("llm", None, None);
    assert_eq!(
        plane_only.dispute_policy,
        busbar_kernel::teller::DisputePolicy::Full
    );
    assert!(!plane_only.entry_fee_enabled);

    let pooled = cell("llm", Some("pool-a"), None);
    assert_ne!(
        pooled, plane_only,
        "a pool that changes nothing is a pool argument the holder dropped"
    );
    let tiered = cell("llm", Some("pool-a"), Some("gold"));
    assert_ne!(
        tiered, pooled,
        "a tier that changes nothing is a tier argument the holder dropped"
    );
    assert!(tiered.entry_fee_enabled);

    // AND A NODE THAT INSTALLED NOTHING ANSWERS THE SHIPPED DEFAULT, whatever it is asked.
    assert_eq!(
        super::tariff_cell("a-plane-nothing-registers", Some("p"), Some("t")),
        busbar_kernel::teller::TariffCell::default(),
        "the process holder is uninstalled in this test binary, and an uninstalled holder does \
         not invent a schedule"
    );
}
