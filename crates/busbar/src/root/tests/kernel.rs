//! Tests for `kernel.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The fee an apply carries reaches the card, and the card a reader already pinned is unmoved.
///
/// The two halves of the swap, asserted together because either alone is a half-truth. A holder
/// that took the new fee but repriced its existing readers would bill a request on rates it was
/// never admitted under; a holder that left its readers alone by never taking the new fee at all
/// would pass the second assertion and be the boot-bound card this replaced. The fee is read as
/// the card's own unit price for its flat line, which is where a configured fee ends up.
#[test]
fn an_apply_moves_the_card_and_leaves_a_pinned_reader_on_the_one_it_took() {
    let holder = RootCard::default();
    assert!(
        holder.pin().is_none(),
        "a holder that has heard no apply prices nothing"
    );

    let absent = |fee| {
        move |generation: u64| {
            busbar_unit_cost::RateCard::absent(
                busbar_unit_cost::RateCardVersion::new(format!("root-llm@{generation}")),
                fee,
            )
        }
    };

    holder.apply(absent(3));
    let admitted = holder.pin().expect("the first apply put a card in place");
    assert_eq!(admitted.card.fee_unit_price_nanos(), 30_000_000);
    assert_eq!(admitted.generation, 1, "the boot resolution is the first");

    // The apply a request in flight must not feel.
    holder.apply(absent(11));
    assert_eq!(
        admitted.card.fee_unit_price_nanos(),
        30_000_000,
        "a reader that pinned before the apply was repriced by it"
    );
    let next = holder.pin().expect("the second apply put a card in place");
    assert_eq!(
        next.card.fee_unit_price_nanos(),
        110_000_000,
        "the apply did not reach the next admission's card"
    );

    // AND THE TWO CARDS ARE TELLABLE APART, which is the whole of what a version is for: the
    // journal stamps the number and the card is named after it, so a posting can be traced back
    // to the configuration that priced it. Two applies used to produce one constant name and a
    // stamp of zero, which said only that a card existed.
    assert_eq!(next.generation, 2);
    assert_ne!(admitted.generation, next.generation);
    assert_eq!(admitted.card.version().as_str(), "root-llm@1");
    assert_eq!(next.card.version().as_str(), "root-llm@2");
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
        // No directory in a cell that is about the ASSEMBLY: the unbound posture, said out loud,
        // which is what the constructor now requires of a caller that has no governance state.
        crate::root::auth_bindings::AuthBindings::without_directory(),
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
        // No directory in a cell that is about the ASSEMBLY: the unbound posture, said out loud,
        // which is what the constructor now requires of a caller that has no governance state.
        crate::root::auth_bindings::AuthBindings::without_directory(),
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
            code: Some(busbar_contract::WireStatus::Http(503)),
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

/// THE INNER ROUTER IS THE ADMIN AUTHORITY, and this is the test the module preamble names.
///
/// An administrative request carrying NO credential at all walks the whole loop and is handed to
/// the mounted surface, which answers it — so nothing in these twelve steps refused it, and what
/// admits or denies an operator today is the router's own check. That is the honest description
/// of a composition built with an empty chain and no revocation view, and writing it down as an
/// assertion is what keeps the steps from reading as a gate they are not yet.
///
/// It fails the day somebody binds a real chain here — which is exactly when the preamble it
/// points at needs rewriting, and when the surface's own check stops being the only one.
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_inner_router_is_the_admin_authority_until_the_chain_is_bound() {
    use tower::ServiceExt;

    let inner = axum::Router::new().fallback(axum::routing::any(|| async { "the surface" }));
    let wrapped =
        crate::root::units_admin::mount(inner, new_kernel(), 1024, ProductionUnits::admin_only);
    let response = wrapped
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/api/v1/admin/audit")
                .body(axum::body::Body::empty())
                .expect("the request builds"),
        )
        .await
        .expect("the router answers");
    assert_eq!(
        response.status(),
        200,
        "a credential-less administrative read was refused by the loop; the authenticate step \
         has become an authority and the module preamble that says it is not needs rewriting"
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
