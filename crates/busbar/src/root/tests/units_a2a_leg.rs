//! Tests for `units_a2a_leg.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::*;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   EVERY BINDING HAS A SOURCE, AND THE TABLE IS CHECKED AGAINST THE STRUCT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The `A2aBindings` field names, read out of that struct's OWN SOURCE.
///
/// A source scan rather than a hand-kept list, because a hand-kept list is exactly the thing the
/// table is supposed to make impossible: the day someone adds a twenty-fourth binding, a hand-kept
/// list agrees with itself and the new field is bound to whatever the assembly happened to have.
fn bindings_fields() -> Vec<String> {
    let src = include_str!("../units_a2a.rs");
    let start = src
        .find("pub struct A2aBindings<'r, S: CellStore> {")
        .expect("the bindings struct is in this file");
    let body = &src[start..];
    let end = body.find("\n}\n").expect("the struct closes");
    body[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("pub ")?;
            let (name, _) = rest.split_once(':')?;
            // A doc line or an attribute is not a field; a field name is an identifier.
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| name.to_string())
        })
        .collect()
}

/// **Every binding the unit reads has a source named for it, and the table names no ghost.**
///
/// This is the finding's own acceptance test. Ten of the twenty-three had no production source at
/// all, and the way that stayed invisible is that nothing anywhere had to account for them: the
/// bindings were built only in tests, and a test supplies whatever it likes. The table is the
/// accounting, and this cell is what keeps it honest in both directions — a field with no row fails,
/// and a row for a field that no longer exists fails too.
#[test]
fn every_binding_of_the_unit_has_a_row_in_the_source_table() {
    let fields = bindings_fields();
    assert_eq!(
        fields.len(),
        24,
        "the bindings carry twenty-four halves; the table below is written per field, so a change \
         in the count is a change this test has to see"
    );
    for field in &fields {
        assert!(
            SOURCES.iter().any(|(name, _)| name == field),
            "`A2aBindings::{field}` has no row in the leg's field→source table: a binding with no \
             source is a control supplied by whoever happened to build the struct"
        );
    }
    for (name, where_) in SOURCES {
        assert!(
            fields.iter().any(|f| f == name),
            "the source table names `{name}`, which is not a field of `A2aBindings` any more"
        );
        assert!(
            !where_.is_empty(),
            "`{name}` has a row and no source in it, which is the same as having no row"
        );
    }
    assert_eq!(
        SOURCES.len(),
        fields.len(),
        "one row per binding, neither more nor fewer"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   A MISSING SOURCE REFUSES BOOT, BY NAME
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// A kernel to lend the two seals from.
fn a_kernel() -> Kernel {
    Kernel::new()
}

/// Every source present, so a cell can take one away and watch the assembly refuse.
fn all_sources(kernel: &Kernel) -> A2aLegSources<'_> {
    A2aLegSources {
        plane: A2aPlane::EMPTY,
        kernel,
        auth: Some(Auth::new(busbar_unit_auth::AuthChain::new(
            Vec::new(),
            false,
        ))),
        auth_bindings: Some(AuthBindings::without_directory()),
        breaker: Some(Arc::new(EveryLaneOpen)),
        guard: Some(GuardPolicy::default()),
        denylist: Some(Denylist::default()),
        pinned: Some(Vec::new()),
        door: Some(Door::new(InMemoryCells::new())),
        groups: Some(GroupTable::default()),
        rates: Some(rates_of(0)),
        store: Some(Arc::new(busbar_core::governance::MemoryStore::new())),
        meter_policy: Some(crate::root::policy::build(
            &crate::root::policy::MeterPolicyConfig::default(),
        )),
        scope_policy: Some(crate::root::units_a2a::scope_policy(ScopePolicy::new())),
        durability: Some(Arc::new(Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                Box::new(busbar_unit_wal::NullShipper::new()),
                Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
            )
            .expect("a memory-buffered journal cannot fail to open"),
        ))),
        key_scopes: None,
        expected_aud: Some(THIS_NODES_AUDIENCE.to_string()),
        priced: false,
        has_key: false,
    }
}

/// The RFC 8707 canonical URI a token has to name to be spendable on this node's A2A mount.
///
/// The shape the rig's own boundary proof reads back off the served protected-resource metadata:
/// `<public_url>/a2a`, and never a name this test invented for the plane.
const THIS_NODES_AUDIENCE: &str = "http://127.0.0.1:8080/a2a";

/// This deployment's rates, at one flat figure and with no card.
///
/// The shape a deployment that configured no `rate_card:` genuinely resolves: an ABSENT card, whose
/// classes price at nothing, beside the per-request figure the door admits against.
fn rates_of(flat: i64) -> Arc<crate::root::kernel::RootRates> {
    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(busbar_unit_cost::RateCard::absent(flat), 0);
    holder.pin_rates(0).expect("the apply put rates in place")
}

/// One deployment's rates WITH a card, so a lane's own class price can be read back.
fn rates_with_card(lane: &str, per_input_unit: f64) -> Arc<crate::root::kernel::RootRates> {
    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(
        busbar_unit_cost::RateCard::from_micro_rates(
            [(
                busbar_unit_cost::LaneClass::new(lane, CLASS_BYTES.as_str()),
                per_input_unit,
            )],
            0,
        ),
        0,
    );
    holder.pin_rates(0).expect("the apply put rates in place")
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE MONEY IS THE NODE'S LIVE RESOLUTION, NEVER THE ONE THE LEG WAS BUILT ON
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **A leg assembled with no resolved rates REFUSES BOOT.**
///
/// Not a nicety about ordering: a leg composed before this deployment's rates were resolved has
/// nothing to admit a unit against, and the only two honest answers are to refuse or to invent a
/// price. Covered by the by-name refusal cell above; restated here because the FIELD it refuses on
/// is `pricer`, and a reader looking for where the money source is proved should find it named.
#[test]
fn a_leg_with_no_resolved_rates_refuses_boot_on_the_money() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.rates = None;
    let refusal = A2aLeg::assemble(sources).expect_err("no rates have been resolved");
    assert_eq!(refusal.field, "pricer");
    assert!(
        refusal.source.contains("ROOT_CARD") || refusal.source.contains("live"),
        "the refusal points at the LIVE holder, which is where this price comes from: got `{}`",
        refusal.source
    );
}

/// **The price a unit is admitted against is the holder's LIVE one, and an apply moves it.**
///
/// The r31g blocker, made a cell. A leg that captured its price at assembly would go on admitting
/// against a fee the operator had already replaced — the engine's own spend projection reprices on
/// every apply, and a boot-bound door would not, so the identity that says the two are one money
/// would hold exactly until somebody edited a figure.
///
/// Asserted against a holder of this cell's own, never the process's: repricing the binary's card
/// to observe a leg would reprice it for everything else running in the same test binary.
#[test]
fn the_price_a_unit_is_admitted_against_follows_the_apply() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.rates = Some(rates_of(3));
    let leg = A2aLeg::assemble(sources).expect("every source is present");

    let holder = crate::root::kernel::RootHistory::default();
    holder.apply(busbar_unit_cost::RateCard::absent(41), 0);
    assert_eq!(
        leg.rates_from(&holder, 0)
            .pricer()
            .price_per_request_cents(),
        41,
        "the apply did not reach the door this leg admits against"
    );
}

/// **And a holder that has heard no apply leaves the leg on the rates it was assembled over.**
///
/// The fallback arm, and the reason it is that value rather than a zero: the figures this node last
/// genuinely resolved are the only honest answer to "what does this cost" when the holder is empty,
/// and a zero would be a price nobody wrote serving as though somebody had.
#[test]
fn an_empty_holder_leaves_the_leg_on_the_rates_it_was_assembled_over() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.rates = Some(rates_of(9));
    let leg = A2aLeg::assemble(sources).expect("every source is present");
    let empty = crate::root::kernel::RootHistory::default();
    assert_eq!(
        leg.rates_from(&empty, 0).pricer().price_per_request_cents(),
        9
    );
}

/// The agent set a byte-price cell reads its lanes off.
static TWO_AGENTS: &[busbar_plane_a2a::Agent] = &[
    busbar_plane_a2a::Agent {
        id: "cheap",
        lane: busbar_contract::ids::LaneId::new("cheap"),
        host: "cheap.example.com",
        transport: busbar_plane_a2a::claims::TRANSPORT_HTTP,
    },
    busbar_plane_a2a::Agent {
        id: "dear",
        lane: busbar_contract::ids::LaneId::new("dear"),
        host: "dear.example.com",
        transport: busbar_plane_a2a::claims::TRANSPORT_HTTP,
    },
];

/// **The byte price the door estimates against is the DEAREST of this deployment's own lanes.**
///
/// An estimate is an upper bound on what the unit about to run could cost, taken before anything is
/// known about which agent it reaches. A mean would under-reserve on the dearest lane and an
/// arbitrary pick would under-reserve on every lane but one — and an under-reserved unit is one
/// admitted against headroom the deployment does not have.
#[test]
fn the_byte_price_estimated_against_is_the_dearest_configured_lane() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.plane = A2aPlane::new(TWO_AGENTS);
    let leg = A2aLeg::assemble(sources).expect("every source is present");

    let dear = rates_with_card("dear", 2.0);
    assert_eq!(
        dear.with_card(|card| leg.bytes_nanos(card)).unwrap_or(0),
        busbar_unit_cost::nano_rate(2.0),
        "the card prices the dear lane and the estimate must take it"
    );
}

/// **A deployment with no agents estimates nothing, rather than panicking on an empty maximum.**
#[test]
fn a_deployment_with_no_agents_estimates_no_byte_price() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    assert_eq!(rates_of(0).with_card(|card| leg.bytes_nanos(card)), Some(0));
}

/// A breaker that benches nothing, so a cell about assembly is not also a cell about readiness.
struct EveryLaneOpen;

impl BreakerView for EveryLaneOpen {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(
        &self,
        _pool: &str,
        _lane: usize,
        _now: u64,
    ) -> Result<(), busbar_unit_trust::Unavailable> {
        Ok(())
    }
}

/// **A source the deployment does not have refuses BOOT, and the refusal names the field.**
///
/// RED FIRST, and the red is the reason this is a refusal rather than a default. Every one of these
/// fields has a "harmless" default sitting right there: an empty auth chain, an empty group table,
/// an empty denylist, a zero price. Every one of those defaults BOOTS CLEAN AND SERVES TRAFFIC — an
/// empty chain admits anonymously, an empty group table says yes to every cap, an empty denylist
/// guards nothing — and none of them has a failing test of its own, because an absent control
/// refuses nothing and therefore breaks nothing. So the assembly refuses, and it says which one.
#[test]
fn a_binding_with_no_source_refuses_boot_naming_the_field() {
    let kernel = a_kernel();

    // One case per field that a real deployment could genuinely be missing, each taking exactly one
    // source away from an otherwise complete set. The pair is (what to remove, what must be named).
    macro_rules! refuses {
        ($field:expr, $take:ident) => {{
            let mut sources = all_sources(&kernel);
            sources.$take = None;
            let refusal = A2aLeg::assemble(sources).err().unwrap_or_else(|| {
                panic!("`{}` has no source, so the leg must not assemble", $field)
            });
            assert_eq!(
                refusal.field, $field,
                "the refusal names the field that has no source, not the first one checked"
            );
            assert!(
                refusal.to_string().contains($field),
                "and an operator reading the boot line sees the field name in it"
            );
            assert!(
                !refusal.source.is_empty(),
                "and is told where the value would have come from"
            );
        }};
    }

    refuses!("auth", auth);
    refuses!("auth_bindings", auth_bindings);
    refuses!("breaker", breaker);
    refuses!("guard", guard);
    refuses!("denylist", denylist);
    refuses!("pinned", pinned);
    refuses!("door", door);
    refuses!("chain", groups);
    // The two money bindings share ONE source — the process's live rates — so there is one case
    // for them and it is named for the first of the pair, exactly as the group table's case is
    // named `chain`.
    refuses!("pricer", rates);
    refuses!("records", store);
    refuses!("meter_policy", meter_policy);
    refuses!("scope_policy", scope_policy);
    refuses!("durability", durability);
    // And the one that is not a binding but a fact the leg reads off every arrival. It refuses for
    // the same reason and is the sharpest case of it: a leg with no audience reads a bearer without
    // checking what it was minted FOR, which admits every token this node's own signing key ever
    // issued for any surface — and boots clean, because an absent audience refuses nothing.
    refuses!("expected_aud", expected_aud);
}

/// **The audience's refusal quotes the decode table, the same way a binding's quotes the bindings'.**
#[test]
fn the_audience_has_a_written_down_source_of_its_own() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.expected_aud = None;
    let refusal = A2aLeg::assemble(sources).expect_err("the audience has no source");
    let row = DECODE_SOURCES
        .iter()
        .find(|(name, _)| *name == "expected_aud")
        .expect("the decode table has a row for it");
    assert_eq!(
        refusal.source, row.1,
        "the refusal's words are the decode table's own row"
    );
    assert!(
        row.1.contains("/a2a"),
        "and the row names the canonical URI the boundary is drawn at"
    );
}

/// **And a complete set assembles.**
///
/// The other half of the cell above: a refusal that fired for every input would be a leg that can
/// never boot, which is a worse failure than the one the refusal exists to prevent.
#[test]
fn a_complete_set_of_sources_assembles() {
    let kernel = a_kernel();
    assert!(
        A2aLeg::assemble(all_sources(&kernel)).is_ok(),
        "every source is present, so the leg assembles"
    );
}

/// **The refusal quotes the table rather than a second copy of it.**
///
/// The words an operator reads at boot and the words in `SOURCES` are the same words. A refusal that
/// spelled its own would be a second place to say where a value comes from, and the one that drifts
/// is the one nobody re-derived.
#[test]
fn the_boot_refusal_quotes_the_source_table() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.denylist = None;
    let refusal = A2aLeg::assemble(sources).expect_err("the denylist has no source");
    let row = SOURCES
        .iter()
        .find(|(name, _)| *name == "denylist")
        .expect("the table has a row for it");
    assert_eq!(
        refusal.source, row.1,
        "the refusal's words are the table's own row"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE TWO RESTATED CONSTANTS ARE PINNED AGAINST THEIR ONE SOURCE
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **The pool this plane admits and meters against is the plane's own path segment.**
///
/// A copy that is checked is not a second opinion. The legacy receiving path admits and meters every
/// A2A unit against the plane's configuration section name, and a root that admitted against a
/// different string would be opening a second set of buckets for one plane's traffic — with both
/// halves looking healthy, because an empty bucket reconciles. The pin is against the plane's OWN
/// path grammar — the segment every agent address carries — rather than against a codec's source,
/// because a plane leg names no codec and a file read at build time is an edge nobody wrote down.
#[test]
fn the_plane_pool_is_the_planes_own_agent_path_segment() {
    use busbar_contract::grammar::{PathSeg, Selector};
    let claimed = busbar_plane_a2a::claims::CLAIMS
        .iter()
        .filter_map(|c| match c.selector {
            Selector::PathPattern(segments) => Some(segments),
            _ => None,
        })
        .flat_map(|segments| segments.iter())
        .find_map(|seg| match seg {
            PathSeg::Lit(lit) if *lit == PLANE_POOL => Some(*lit),
            _ => None,
        })
        .expect("the plane's claim table carries the agent path segment");
    assert_eq!(
        PLANE_POOL, claimed,
        "the root's restated pool name and the plane's own agent path segment are one string"
    );
}

/// **The breaker keyspace prefix is the substrate's own.**
///
/// `busbar_substrate::store::agent_key` is the single spelling, and the legacy route path keys its
/// breaker cells with it. A root whose pool view stripped a different prefix would answer
/// `is_configured` false for every agent a deployment registered.
#[test]
fn the_pool_prefix_is_the_substrates_own_agent_key() {
    let substrate = include_str!("../../../../busbar-substrate/src/store.rs");
    // Narrowed to `agent_key`'s own body: the sibling `tool_key` formats the MCP prefix a few lines
    // above, and a scan that took the first `format!` in the file would pin this plane's keyspace
    // against the other plane's — which is a green test asserting the wrong fact.
    let body = substrate
        .split_once("pub fn agent_key(agent: &str) -> String {")
        .expect("the substrate declares agent_key")
        .1;
    let declared = body
        .lines()
        .find_map(|l| l.trim().strip_prefix("format!("))
        .and_then(|rest| rest.split('"').nth(1))
        .expect("agent_key formats its prefix as a literal");
    assert!(
        declared.starts_with(POOL_PREFIX_AGENT),
        "the root's restated prefix `{POOL_PREFIX_AGENT}` is the one `agent_key` formats \
         (`{declared}`)"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE REFUSED STEPS
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The context one unit of this plane is walked under.
fn a_ctx() -> UnitCtx {
    UnitCtx {
        key: busbar_caps::UnitKey::new(1),
        origin: busbar_caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

/// **A refused Verify never reaches the meter.**
///
/// RED FIRST, and this is the money cell. The step log is what proves it rather than an absence of a
/// number: a meter that folded for a unit the trust unit refused would post against a destination
/// nobody was allowed to reach, and it would do so with a perfectly plausible figure. The loop's own
/// ending carries the step it stopped at, so the assertion is that the ending IS a Verify refusal —
/// and therefore that Meter, which runs three steps later, did not.
#[test]
fn a_refused_verify_never_reaches_the_meter() {
    let kernel = a_kernel();
    // NOTHING IS REGISTERED, so the plane's own destination for a hop is the unreachable one — the
    // empty host the trust unit refuses against the allow-list. That is the plane's shape and not a
    // fixture's: a deployment with no `agents:` gets exactly this.
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let ended = walk_one(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"message/send"}"#,
    );

    let step = refused_at(&ended).expect("a unit with nowhere to go is refused, not completed");
    // THE STEP LOG IS THE ASSERTION, and the step is named exactly. The ending carries the step the
    // loop stopped at, and the ten run in a fixed order — so an ending AT VERIFY is the loop saying,
    // in its own words, that Route, Meter and Audit did not run. An assertion that merely looked for
    // "no posting" would pass for a metered unit whose fold happened to come out at zero, which is
    // the failure this cell exists to catch rather than the one it would then be describing.
    assert_eq!(
        step,
        busbar_caps::StepName::Verify,
        "the trust unit refuses the destination the plane calls unreachable, and the unit ends there"
    );
    assert!(
        step < busbar_caps::StepName::Meter,
        "and Verify is before Meter, so the meter did not fold for a unit that was told no"
    );
}

/// **An Approve refusal ends the unit.**
///
/// The scope unit reads silence as a denial, and an anonymous caller holds read-only grants. A class
/// the policy declares as `Full` is therefore refused at Approve — and a refusal at Approve is the
/// END of the unit, not a step it walks past with a flag set. Asserting the ending rather than a
/// return value is the point: a step that refused and let the loop continue would settle money for a
/// unit the deployment's own policy said no to.
#[test]
fn an_approve_refusal_ends_the_unit() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let ended = walk_one(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/cancel"}"#,
    );
    assert!(
        matches!(ended, Ended::Settled { .. } | Ended::AlreadySettled),
        "the loop reached an ending"
    );
    // Whatever step it stopped at, it stopped: an ending that completed would be this plane serving
    // a mutating operation to a caller that presented no credential.
    assert!(
        !completed(&ended),
        "an anonymous caller does not complete a mutating operation of this plane"
    );
}

/// **The leg IS a `PlaneLeg`, and the driver walks an arrival against it.**
///
/// The sentence the previous cut left open. `LoopDriver` was widened to hold a `&dyn PlaneLeg`
/// precisely so a leg whose units are assembled per arrival could be driven, and until now the only
/// implementors were the blanket one over `Units` — legs whose units do NOT depend on the arrival —
/// plus a test double. This drives a real arrival through the real driver against the real leg,
/// which is the composition the mount will hand a listener and the one thing a type check alone does
/// not prove: the coercion, the lifetimes and the ten steps together.
///
/// The ANSWER is not asserted here beyond its shape. What this plane says on the wire is the plane's
/// own encoder's business and is judged by the conformance battery against a real agent, not by a
/// root cell with nothing registered.
#[test]
fn the_driver_walks_an_arrival_against_this_leg() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let gauge = busbar_kernel::slice::ConcurrencyGauge::new();
    let canary = busbar_caps::Canary::new();
    let plane = A2aPlane::EMPTY;
    // The coercion is the point of the line: a `&A2aLeg` where a `&dyn PlaneLeg` is expected, with
    // no adapter between them.
    let driver = crate::root::transports::LoopDriver::new(&kernel, &leg, &gauge, &canary, &plane);

    let facts: [(&str, &str); 3] = [
        ("path", "/a2a"),
        ("method", "POST"),
        ("peer", "127.0.0.1:1"),
    ];
    let chain: [&'static str; 2] = ["tcp", "http"];
    let answer = busbar_contract::transport::UnitDriver::drive(
        &driver,
        busbar_contract::transport::Arrival {
            facts: &facts,
            body: br#"{"jsonrpc":"2.0","id":1,"method":"message/send"}"#,
            transport: "http",
            chain: &chain,
            operation: None,
            bar: busbar_contract::transport::Bar::Open,
        },
        // The surface the arrival was addressed against. Empty here because the arrival names a
        // MOUNT rather than a route — the operation lives inside the document, which is what
        // `operation: None` above says — and the driver reads two fields off the operation and none
        // off the surface.
        &busbar_contract::transport::WireSurface {
            bindings: &[],
            operations: &[],
        },
    );

    // The driver narrowed the loop's ending into one of the eight words a transport can render, and
    // it is NOT `Completed`: nothing is registered, so the trust unit had nowhere to send this and
    // said so. A `Completed` here would mean the loop ran a unit to the end against an empty host.
    assert_ne!(
        answer.outcome,
        busbar_contract::transport::Outcome::Completed,
        "a node with no agent configured does not complete an agent call"
    );
    // AND THE BODY IS THE PLANE'S OR IT IS EMPTY. The driver renders no prose of its own — that is
    // the whole content of the seam — so whatever came back is either the plane's own refusal
    // document or nothing at all.
    assert!(
        answer.body.is_empty() || serde_json::from_slice::<serde_json::Value>(&answer.body).is_ok(),
        "the body a caller receives is the plane's own document, not something the driver wrote"
    );
}

/// **Every operation class this plane declares walks to an ending.**
///
/// Twelve classes, twelve endings, no panic. The cell is cheap and the thing it forbids is not: a
/// producer that reached a class the plane's own tables do not answer for would panic on the request
/// path, and it would do so for exactly one method that nobody happened to send in a fixture.
#[test]
fn every_declared_class_walks_to_an_ending() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    for op in declared_classes() {
        let draft = A2aDraft::from_decoded(
            leg.plane(),
            &Decoded {
                op: Some(*op),
                request_bytes: 64,
                ..Decoded::default()
            },
            busbar_contract::wire::ArrivalRecord {
                source: "127.0.0.1:1".to_string(),
                port: 0,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: vec!["tcp", "http"],
            },
        );
        // The producer answered from the plane's own tables for this class, which is what the leg
        // hands the ten steps. A class the plane does not answer for would have panicked above.
        assert_eq!(draft.op, Some(*op), "{op:?}: the class is carried through");
    }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE DISPATCH SEAM: THE UNITS ARE THE GATE, THE SURFACE IS THE ANSWER
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// A surface that counts how many times it was asked and answers with bytes nothing else could
/// produce.
///
/// The COUNT is the whole instrument. Every cell below is about whether the surface was reached, and
/// an assertion on the answer alone cannot tell "the loop refused before the seam" apart from "the
/// seam was driven and its answer was then discarded" — which are the same bytes to a caller and
/// completely different facts about what ran. A surface that ran for a refused unit has executed an
/// operation on the path where nothing is supposed to execute.
#[derive(Default)]
struct CountingSurface {
    asked: std::sync::atomic::AtomicUsize,
}

impl CountingSurface {
    /// How many times the loop reached the seam.
    fn asked(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The bytes this double answers with, which no step of the loop could have written.
const SURFACE_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"from":"the surface"}}"#;

/// The status it answers with, deliberately not one the loop's own narrowing would produce.
const SURFACE_STATUS: u16 = 207;

impl crate::root::transports::MountDispatch for CountingSurface {
    fn execute(
        &self,
        _op: busbar_contract::ids::OpClassId,
    ) -> crate::root::transports::MountedReply {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        axum::http::Response::builder()
            .status(SURFACE_STATUS)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(SURFACE_BODY.to_vec()))
            .expect("the double's answer always builds")
    }

    fn collect(&self, _body: axum::body::Body) -> Option<Vec<u8>> {
        // A DOUBLE ANSWERS FROM THE BODY IT WROTE. There is no runtime on the far side of this seam to
        // step onto and no surface to wait for: the bytes are the ones `execute` just handed back, so
        // reading them is returning them. What the cells are asserting is what the LOOP does with an
        // answer, and that is unchanged by where the double keeps it.
        Some(SURFACE_BODY.to_vec())
    }
}

/// **The Route step drives the seam, and what comes back out is the surface's own bytes.**
///
/// RED FIRST: before the seam existed this walk answered with a plan and an EMPTY frame — the leg ran
/// ten steps and served nothing, which is the sentence the previous cut ended on. The three
/// assertions are the three halves of the seam: the surface was asked exactly once, the status and
/// the headers came back through the answer, and the body reached the frame the Encode step reports.
///
/// The bytes are ones NO step of this loop could have written. A cell that asserted on a plausible
/// document would pass for a root that had rendered its own — which is the one thing the whole seam
/// exists to make impossible.
#[test]
fn the_route_step_drives_the_seam_and_the_surface_bytes_come_back_out() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let surface = CountingSurface::default();

    let (ended, answer) = serve_one(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
        Some(&surface),
    );

    assert_eq!(
        surface.asked(),
        1,
        "a unit that reached Route asked the surface exactly once — not never, and not twice"
    );
    let answer = answer.expect("a unit that reached the seam carries the surface's answer out");
    assert_eq!(
        answer.status, SURFACE_STATUS,
        "the status is the surface's, not one this root narrowed an ending into"
    );
    assert_eq!(
        answer.body, SURFACE_BODY,
        "and so is every byte of the body"
    );
    assert_eq!(
        answer.headers,
        vec![("content-type".to_string(), "application/json".to_string())],
        "and the headers it emitted travel with it"
    );
    // AND THE ENCODE STEP REPORTS THEM. The frame is what a driver hands a transport, so a body that
    // reached the answer and not the frame would be a body the driven path still cannot serve.
    assert_eq!(
        frame_bytes(&ended).as_deref(),
        Some(SURFACE_BODY),
        "the frame the loop ends with carries the surface's bytes"
    );
}

/// **A Verify refusal ends the unit BEFORE the surface is touched.**
///
/// RED FIRST, and the red is the reason the seam is at Route and not above it. With nothing
/// registered the trust unit has nowhere to send an agent call and refuses — and a seam driven
/// anywhere earlier, or driven unconditionally on the way past, would have executed the operation for
/// a caller the deployment's own guards said no to. The count is zero, which is a fact about what RAN
/// rather than about what came back.
#[test]
fn a_verify_refusal_never_touches_the_surface() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let surface = CountingSurface::default();

    let (ended, answer) = serve_one(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"message/send"}"#,
        Some(&surface),
    );

    assert_eq!(
        refused_at(&ended),
        Some(busbar_caps::StepName::Verify),
        "the trust unit refuses the destination the plane calls unreachable"
    );
    assert_eq!(
        surface.asked(),
        0,
        "and the surface was never asked, because Verify runs before Route"
    );
    assert!(
        answer.is_none(),
        "so there is no answer to carry out, and the mount renders the loop's refusal instead"
    );
}

/// **An Approve refusal ends the unit BEFORE the surface is touched.**
///
/// The scope unit reads silence as a denial and an anonymous caller holds read-only grants, so a
/// class this plane declares `Full` is refused at Approve. Same instrument, different gate: the
/// surface answers a caller whose grant does not reach the operation exactly never.
#[test]
fn an_approve_refusal_never_touches_the_surface() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let surface = CountingSurface::default();

    let (ended, answer) = serve_one(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/pushNotificationConfig/set"}"#,
        Some(&surface),
    );

    assert!(
        !completed(&ended),
        "an under-scoped caller does not complete"
    );
    assert_eq!(
        surface.asked(),
        0,
        "and the surface was never asked for a unit the scope policy refused"
    );
    assert!(
        answer.is_none(),
        "so nothing of the surface's is carried out"
    );
}

/// **An Admit refusal ends the unit BEFORE the surface is touched.**
///
/// The third gate and the money one. A caller bound to a group this node's configuration does not
/// have is fail-closed at the door — `chain` is `None`, which the admission step renders as over
/// budget — and a surface asked for that unit would be work done, and possibly value delivered, for a
/// request that was never paid for.
#[test]
fn an_admit_refusal_never_touches_the_surface() {
    let kernel = a_kernel();
    let surface = CountingSurface::default();

    // The door is asked about a chain the leg could not resolve. Driven through the units rather than
    // through the leg because the leg resolves the chain from the group table it was assembled with,
    // and the fail-closed arm is precisely the case where that resolution came back empty.
    let refused = admit_with_no_chain(&kernel, &surface);
    assert_eq!(
        refused,
        Some(busbar_caps::ReasonCode::OverBudget),
        "a caller whose caps could not be read is refused at the door"
    );
    assert_eq!(
        surface.asked(),
        0,
        "and Admit runs before Route, so the surface was never asked"
    );
}

/// The reason the admission step refuses a unit whose chain could not be resolved.
///
/// One walk of the door with the binding the leg would have built, minus the chain. It reads the
/// refusal off the step's own decision rather than off an ending, because this is a cell about which
/// gate fired and not about how the loop narrowed it.
fn admit_with_no_chain(
    kernel: &Kernel,
    surface: &CountingSurface,
) -> Option<busbar_caps::ReasonCode> {
    use busbar_kernel::teller::Units as _;
    let leg = A2aLeg::assemble(all_sources(kernel)).expect("every source is present");
    let pools = leg.pools();
    let kinds = leg.kinds(records::SCHEMA_TASK, records::OP_GET);
    let draft = A2aDraft::from_decoded(
        leg.plane(),
        &Decoded {
            op: Some(ops::OP_TASK_LIST),
            request_bytes: 64,
            ..Decoded::default()
        },
        busbar_contract::wire::ArrivalRecord {
            source: "127.0.0.1:1".to_string(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["tcp", "http"],
        },
    );
    // Everything the leg would have bound, and `chain: None` — the caller bound to a group this
    // node's configuration does not have.
    let rates = rates_of(0);
    let bindings = leg.bindings(
        &pools,
        &kinds,
        &[],
        None,
        1_700_000_000,
        0,
        Some(surface),
        rates.pricer(),
        0,
        false,
    );
    let units = A2aUnits::new(bindings, draft, Grants::of(Scope::ReadOnly));
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let slip = busbar_kernel::slice::GroupLeaseSlip::new();
    let decision = units.admit(
        &busbar_caps::UnitToken::mint(&seal),
        &busbar_caps::AdmitToken::mint(&seal),
        &a_ctx(),
        &busbar_caps::PrincipalId::new("anyone"),
        &[],
        &slip,
    );
    decision.into_result(&seal).err().map(|r| r.reason())
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE AUDIENCE BOUNDARY, AT THE LEG
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// A token this node's own signing key minted, and the audience it was minted FOR.
///
/// Three of them, because three is what the boundary is drawn between: one bound to this mount, one
/// bound to nothing at all — the ORDINARY data-plane token every deployment already issues — and one
/// bound to a different resource. The second is the dangerous one and the reason the cells below
/// exist: it is not a forgery, it is a credential this node minted and honours elsewhere.
fn audience_carried_by(credential: &str) -> Option<Option<&'static str>> {
    match credential {
        "bound-to-this-mount" => Some(Some(THIS_NODES_AUDIENCE)),
        "bound-to-nothing" => Some(None),
        "bound-elsewhere" => Some(Some("https://example.invalid/mcp")),
        _ => None,
    }
}

/// A key directory that enforces the plane boundary the way the node's real verifier does.
///
/// The match is `busbar_substrate::governance::signing::SigningKey::verify`'s own, arm for arm: a
/// plain token is admissible where nothing is expected, a bound token exactly where its audience is
/// expected, and nothing else falls through. Mirroring it rather than simplifying it is what makes
/// these cells about the leg — a double that just compared `expected_aud` to a constant would go
/// green for a leg that supplied no audience at all, because "no audience" would simply never match.
struct TheNodesOwnBoundary;

impl crate::root::kernel::auth_bindings::VirtualKeyDirectory for TheNodesOwnBoundary {
    fn verify(
        &self,
        credential: &str,
        _now: u64,
        expected_aud: Option<&str>,
    ) -> Option<crate::root::kernel::auth_bindings::KeyFacts> {
        let carried = audience_carried_by(credential)?;
        let admissible = match (expected_aud, carried) {
            (None, None) => true,
            (Some(expected), Some(aud)) => expected == aud,
            _ => false,
        };
        admissible.then(|| crate::root::kernel::auth_bindings::KeyFacts {
            id: "key-a2a-1".to_string(),
            name: "an approved key".to_string(),
        })
    }

    fn revoked(&self, _credential: &str) -> bool {
        false
    }
}

/// A leg whose door is shut to everything but a token minted for THIS node's mount.
fn a_leg_that_checks_the_audience(kernel: &Kernel) -> A2aLeg {
    let mut sources = all_sources(kernel);
    // The signed-key arm and no boxed module: the door stays shut, and the arm is the one thing
    // that can open it — which is what makes these cells about the audience rather than about a
    // chain that would have admitted anyone.
    sources.auth = Some(Auth::new(busbar_unit_auth::AuthChain::new(
        Vec::new(),
        true,
    )));
    sources.auth_bindings = Some(AuthBindings::new(Arc::new(TheNodesOwnBoundary)));
    A2aLeg::assemble(sources).expect("every source is present")
}

/// **A bearer minted for another audience is refused at the door, and NEVER reaches the surface.**
///
/// RED FIRST, and the red is the whole reason the audience is a boot source rather than an option.
/// Before this cut the leg's decode answered `expected_aud: None` for every arrival — so the chain
/// was asked "is this token any good" without ever being told what it had to have been minted FOR,
/// and every token this node's own signing key had ever issued, for any surface, opened this one.
/// The rig's boundary proof is exactly this probe and it would have gone green on that leg, because
/// nothing on the serving path read the credential at all.
///
/// THE COUNT IS THE INSTRUMENT. A refusal whose bytes look right but whose surface already ran is an
/// operation executed for a caller the door said no to, and no assertion on the answer can tell the
/// two apart.
#[test]
fn a_bearer_minted_for_another_audience_never_reaches_the_surface() {
    let kernel = a_kernel();
    let leg = a_leg_that_checks_the_audience(&kernel);
    let surface = CountingSurface::default();

    let (ended, answer) = serve_presenting(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
        // The same bytes the node would accept, presented under an expectation this node does not
        // hold: the directory above mints only for `THIS_NODES_AUDIENCE`.
        Some("Bearer bound-to-nothing"),
        Some(&surface),
    );

    assert_eq!(
        refused_at(&ended),
        Some(busbar_caps::StepName::Authenticate),
        "a token this node's audience does not cover is refused at the step that reads it"
    );
    assert_eq!(
        surface.asked(),
        0,
        "and the surface was never asked, so nothing was executed for it"
    );
    assert!(
        answer.is_none(),
        "so there is no answer to carry out and the mount renders the loop's own refusal"
    );
}

/// **And the token minted FOR this mount is admitted, and does reach it.**
///
/// The other half, and the half that makes the cell above a boundary rather than a door shut to
/// everything: a leg that refused every credential would pass the counterfactual and serve nobody.
/// The audience the token carries is the one this node publishes, so it is spent here.
#[test]
fn a_bearer_minted_for_this_mount_is_admitted_and_reaches_the_surface() {
    let kernel = a_kernel();
    let leg = a_leg_that_checks_the_audience(&kernel);
    let surface = CountingSurface::default();

    let (_ended, answer) = serve_presenting(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
        Some("Bearer bound-to-this-mount"),
        Some(&surface),
    );

    assert_eq!(
        surface.asked(),
        1,
        "the credential named this node's own mount, so the unit walked through to the seam"
    );
    assert_eq!(
        answer.map(|a| a.status),
        Some(SURFACE_STATUS),
        "and what came back is the surface's answer"
    );
}

/// **The scheme word is stripped once, and only for a carrier the PLANE declared.**
///
/// Two properties in one cell because they are one decision. The chain is handed the secret and not
/// the carrier's spelling of it — a directory comparing against `Bearer a-real-token` would never
/// match — and the carrier is matched against the alternatives the plane's own claims declare rather
/// than against a literal here, case-insensitively, because `bearer` is a case-insensitive token on
/// the wire.
#[test]
fn the_carrier_is_the_planes_own_and_the_secret_reaches_the_chain_bare() {
    let kernel = a_kernel();
    let leg = a_leg_that_checks_the_audience(&kernel);

    for presented in ["Bearer bound-to-this-mount", "bearer bound-to-this-mount"] {
        let surface = CountingSurface::default();
        let _ = serve_presenting(
            &leg,
            &kernel,
            br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
            Some(presented),
            Some(&surface),
        );
        assert_eq!(
            surface.asked(),
            1,
            "`{presented}` carries the same secret as every other spelling of the same carrier"
        );
    }

    // And a carrier the plane never declared narrows to nothing. Narrowing to nothing inside a
    // non-empty declared set is a refusal, which is the fail-closed answer: a node that quietly
    // accepted an undeclared scheme would be honouring a credential nobody wrote down.
    let surface = CountingSurface::default();
    let (ended, _) = serve_presenting(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
        Some("Basic bound-to-this-mount"),
        Some(&surface),
    );
    assert_eq!(
        refused_at(&ended),
        Some(busbar_caps::StepName::Authenticate),
        "a carrier this plane's claims do not declare does not open it"
    );
    assert_eq!(surface.asked(), 0, "and nothing was executed for it");
}

/// **The alternatives the leg narrows within are the plane's own, not a copy.**
///
/// Read off `claims::CLAIMS` rather than restated, so a claim that gained an alternative gains it
/// here too. A literal in the root would be a second declaration of what this protocol accepts, and
/// the one that drifts is the one nobody re-derived.
#[test]
fn the_declared_alternatives_are_read_off_the_planes_claims() {
    let from_the_plane: Vec<&str> = busbar_plane_a2a::claims::CLAIMS
        .iter()
        .flat_map(|claim| claim.scheme_alternatives.iter().copied())
        .collect();
    assert!(
        !from_the_plane.is_empty(),
        "this plane declares credentialed claims, or there is no boundary to draw"
    );
    for alt in declared_schemes() {
        assert!(
            from_the_plane.contains(alt),
            "`{alt}` is narrowed to by the leg and declared by no claim of this plane"
        );
    }
    for alt in &from_the_plane {
        assert!(
            declared_schemes().contains(alt),
            "the plane declares `{alt}` and the leg would refuse a caller that presented it"
        );
    }
}

/// **An arrival that presented nothing still presents nothing.**
///
/// The three open surfaces of this protocol carry no credential by design, and the anonymous posture
/// has to stay reachable: a leg that invented an empty bearer would be telling the chain a credential
/// was presented and is blank, which is a different — and worse — statement than "none arrived".
#[test]
fn an_arrival_with_no_credential_fact_presents_none() {
    let kernel = a_kernel();
    let leg = A2aLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let surface = CountingSurface::default();
    // The permissive fixture chain is open, so this walks exactly as it did before the credential
    // fact existed — which is the byte-identity this cut rests on for an arrival that carries none.
    let (_ended, answer) = serve_presenting(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tasks/list"}"#,
        None,
        Some(&surface),
    );
    assert_eq!(surface.asked(), 1, "an anonymous caller is still served");
    assert!(answer.is_some(), "and its answer still comes back out");
}

/// The bytes the loop's ending carries on its frame, where it carries one.
fn frame_bytes(ended: &Ended) -> Option<Vec<u8>> {
    match ended {
        Ended::Settled { frame, .. } => frame.as_ref().map(|f| f.bytes.as_slice().to_vec()),
        Ended::AlreadySettled => None,
    }
}

/// Walk one body through the leg WITH a seam, and take back both halves.
fn serve_one(
    leg: &A2aLeg,
    kernel: &Kernel,
    body: &[u8],
    dispatch: Option<&dyn crate::root::transports::MountDispatch>,
) -> (Ended, Option<crate::root::transports::PlaneAnswer>) {
    serve_presenting(leg, kernel, body, None, dispatch)
}

/// The same walk, for an arrival that PRESENTED something.
///
/// The credential travels as the transport's own reserved fact and WHOLE — the scheme word included
/// — because that is what a mounted arrival publishes. A helper that handed the leg a bare token
/// would be testing a strip this leg would then never have to do.
fn serve_presenting(
    leg: &A2aLeg,
    kernel: &Kernel,
    body: &[u8],
    credential: Option<&str>,
    dispatch: Option<&dyn crate::root::transports::MountDispatch>,
) -> (Ended, Option<crate::root::transports::PlaneAnswer>) {
    let mut facts: Vec<(&str, &str)> = vec![
        ("path", "/a2a"),
        ("method", "POST"),
        ("peer", "127.0.0.1:1"),
    ];
    if let Some(credential) = credential {
        facts.push((busbar_contract::transport::facts::CREDENTIAL, credential));
    }
    let chain: [&'static str; 2] = ["tcp", "http"];
    let arrival = busbar_contract::transport::Arrival {
        facts: &facts,
        body,
        transport: "http",
        chain: &chain,
        operation: None,
        bar: busbar_contract::transport::Bar::Open,
    };
    let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
        &kernel.admit_token(),
        busbar_caps::PrincipalId::new(""),
        0,
    ));
    let leases = busbar_kernel::slice::LeaseCell::new();
    let meter = busbar_kernel::teller::AccrualMeter::new();
    let gauge = busbar_kernel::slice::ConcurrencyGauge::new();
    let canary = busbar_caps::Canary::new();
    leg.serve(
        &arrival,
        kernel,
        &a_ctx(),
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
        dispatch,
    )
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   AN OPEN ADDRESS IS OPEN, AND IT IS THE ADDRESS THAT DECIDES
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// What the leg made of one request line, with no credential on it.
fn decode_at(leg: &A2aLeg, path: &str, method: &str, body: &[u8]) -> Decoded {
    let facts: [(&str, &str); 3] = [("path", path), ("method", method), ("peer", "127.0.0.1:1")];
    let chain: [&'static str; 2] = ["tcp", "http"];
    leg.decode(
        &busbar_contract::transport::Arrival {
            facts: &facts,
            body,
            transport: "http",
            chain: &chain,
            operation: None,
            bar: busbar_contract::transport::Bar::Open,
        },
        0,
    )
}

/// **THE DISCOVERY ADDRESSES DEMAND NO AUDIENCE, because the plane declares them OPEN.**
///
/// RED FIRST, and the red was a live 401. This protocol serves its protected-resource metadata and
/// its own agent card unauthenticated — that is where a conformant client looks FIRST, and the
/// metadata document is how a caller learns which audience to ask for. A leg that demanded an
/// audience there refused every caller before it could discover what to present, and the shipped
/// surface answered both with 200.
///
/// The reason it happened is the reason the fix is shaped this way: openness was read off the
/// OPERATION, and this protocol's card operation is served at three addresses — two open discovery
/// ones and one credentialed extended card. An operation is the wrong granularity for a question the
/// declaration answers per ADDRESS.
#[test]
fn the_discovery_addresses_demand_no_audience() {
    let kernel = a_kernel();
    let leg = a_leg_that_checks_the_audience(&kernel);
    for path in [
        "/.well-known/agent-card.json",
        "/.well-known/oauth-protected-resource/a2a",
    ] {
        let read = decode_at(&leg, path, "GET", b"");
        assert!(
            read.op.is_some(),
            "`{path}` is an address this plane declares, so it must be a unit it has"
        );
        assert_eq!(
            read.expected_aud, None,
            "`{path}` is declared OPEN and must not demand an audience"
        );
        assert!(
            read.declared_schemes.is_empty(),
            "`{path}` narrows within nothing, because it declares no scheme to narrow within"
        );
    }
}

/// **And the credentialed addresses still demand one.**
///
/// The other half, and the one that must not be lost while fixing the first: the extended card is
/// the SAME operation as the discovery card and is served under a credential, so a fix that read
/// openness off the operation would open it. The document mount is the second: the operation lives
/// inside the body there, no open target addresses `POST /a2a`, and it stays credentialed.
#[test]
fn the_credentialed_addresses_still_demand_an_audience() {
    let kernel = a_kernel();
    let leg = a_leg_that_checks_the_audience(&kernel);
    for (path, method, body) in [
        ("/a2a/extendedAgentCard", "GET", &b""[..]),
        (
            "/a2a",
            "POST",
            &br#"{"jsonrpc":"2.0","id":1,"method":"message/send"}"#[..],
        ),
    ] {
        let read = decode_at(&leg, path, method, body);
        assert_eq!(
            read.expected_aud.as_deref(),
            Some(THIS_NODES_AUDIENCE),
            "`{method} {path}` is served under a credential and must demand this node's audience"
        );
        assert!(!read.declared_schemes.is_empty());
    }
}

/// **The push callback stays open, which is the address that was open before this cut.**
#[test]
fn the_push_callback_address_stays_open() {
    let kernel = a_kernel();
    let leg = a_leg_that_checks_the_audience(&kernel);
    assert_eq!(
        decode_at(&leg, "/a2a/push", "POST", b"{}").expected_aud,
        None
    );
}

/// Walk one request line through the leg, with the deployment's own door in front of it.
fn walk_at(leg: &A2aLeg, kernel: &Kernel, path: &str, method: &str, body: &[u8]) -> Ended {
    use crate::root::transports::PlaneLeg as _;
    let facts: [(&str, &str); 3] = [("path", path), ("method", method), ("peer", "127.0.0.1:1")];
    let chain: [&'static str; 2] = ["tcp", "http"];
    let arrival = busbar_contract::transport::Arrival {
        facts: &facts,
        body,
        transport: "http",
        chain: &chain,
        operation: None,
        bar: busbar_contract::transport::Bar::Open,
    };
    let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
        &kernel.admit_token(),
        busbar_caps::PrincipalId::new(""),
        0,
    ));
    let leases = busbar_kernel::slice::LeaseCell::new();
    let meter = busbar_kernel::teller::AccrualMeter::new();
    let gauge = busbar_kernel::slice::ConcurrencyGauge::new();
    let canary = busbar_caps::Canary::new();
    leg.walk(
        &arrival,
        kernel,
        &a_ctx(),
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    )
}

/// A leg whose deployment configured a CLOSED front door — the shape `auth.chain: [keys]` resolves
/// to, where an anonymous caller is denied.
fn a_leg_behind_a_closed_door(kernel: &Kernel) -> A2aLeg {
    let mut sources = all_sources(kernel);
    sources.auth = Some(Auth::new(
        crate::root::data_plane::data_chain(&[crate::root::data_plane::ChainPosition {
            provider: "keys",
            module: busbar_unit_auth::chain::KEYS_MODULE,
        }])
        .expect("the built-in arm resolves"),
    ));
    sources.expected_aud = Some(THIS_NODES_AUDIENCE.to_string());
    A2aLeg::assemble(sources).expect("every source is present")
}

/// **AN ANONYMOUS CALLER REACHES A DECLARED-OPEN ADDRESS THROUGH A CLOSED DEPLOYMENT.**
///
/// RED FIRST, and the red was a live 401 on the two addresses a conformant client reads FIRST. The
/// deployment's chain is the deployment's answer for the addresses it guards; a protocol's discovery
/// endpoints are not among them, and running the chain there refuses every caller before it can
/// learn which audience to present. The previous release serves both with its auth middleware
/// bypassed; this is that behaviour, reached through the plane's own declaration.
#[test]
fn an_anonymous_caller_reaches_a_declared_open_address_through_a_closed_deployment() {
    let kernel = a_kernel();
    let leg = a_leg_behind_a_closed_door(&kernel);
    for path in [
        "/.well-known/agent-card.json",
        "/.well-known/oauth-protected-resource/a2a",
    ] {
        let ended = walk_at(&leg, &kernel, path, "GET", b"");
        assert_ne!(
            crate::root::transports::outcome_of(&ended),
            busbar_contract::transport::Outcome::Unauthenticated,
            "`{path}` is declared OPEN and must not be refused for want of a credential"
        );
    }
}

/// **And a CREDENTIALED address behind the same closed deployment still refuses one.**
///
/// The half that must not be lost while fixing the first. A fix that opened the door for every
/// address of this protocol would serve the whole plane anonymously on a deployment whose operator
/// configured a chain — which is the same defect pointed the other way, and the worse one.
#[test]
fn a_credentialed_address_behind_a_closed_deployment_still_refuses_an_anonymous_caller() {
    let kernel = a_kernel();
    let leg = a_leg_behind_a_closed_door(&kernel);
    let ended = walk_at(
        &leg,
        &kernel,
        "/a2a",
        "POST",
        br#"{"jsonrpc":"2.0","id":1,"method":"message/send"}"#,
    );
    assert_eq!(
        crate::root::transports::outcome_of(&ended),
        busbar_contract::transport::Outcome::Unauthenticated,
        "the document mount is served under a credential and an anonymous caller is refused there"
    );
}

/// **A DECLARED-OPEN address is not closed again by the scope step.**
///
/// RED FIRST, and the red broke push delivery. This protocol's push callback is declared OPEN — a
/// fronted agent posts a task update to it and the AUTHORITY is the push token inside the request,
/// which is the surface's to check and is where the shipped release checks it. A loop that admitted
/// the caller anonymously at the door and then refused it at Approve turned every real push delivery
/// into a 403 before the surface ever saw the token, which is a working feature deleted by a
/// composition rather than by a decision.
///
/// So an open address carries the scope its own operation declares. The narrowness is the whole
/// safety argument: only an address the plane's surface declares OPEN reaches this at all, this
/// protocol declares three, and two of them are read-only discovery.
#[test]
fn a_declared_open_address_is_not_closed_again_by_the_scope_step() {
    let kernel = a_kernel();
    let leg = a_leg_behind_a_closed_door(&kernel);
    let ended = walk_at(&leg, &kernel, "/a2a/push", "POST", b"{}");
    assert_ne!(
        crate::root::transports::outcome_of(&ended),
        busbar_contract::transport::Outcome::Forbidden,
        "the push callback is declared open and its authority is the token the surface reads"
    );
}

/// **And a CREDENTIALED address is still judged against what an anonymous caller holds.**
///
/// The other half. An open address's grants are its own declaration's; every other address is
/// judged against the read-only set an unidentified caller holds, and a fix that widened that would
/// hand the whole plane's write verbs to anybody.
#[test]
fn a_credentialed_address_is_still_judged_against_the_anonymous_set() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.auth = Some(Auth::new(crate::root::data_plane::open_door()));
    let leg = A2aLeg::assemble(sources).expect("every source is present");
    let ended = walk_at(
        &leg,
        &kernel,
        "/a2a",
        "POST",
        br#"{"jsonrpc":"2.0","id":1,"method":"message/send"}"#,
    );
    assert_eq!(
        crate::root::transports::outcome_of(&ended),
        busbar_contract::transport::Outcome::Forbidden,
        "an anonymous caller through an open FRONT DOOR still holds only the read-only set, and \
         `message/send` is not in it"
    );
}

/// Walk one body through the leg, as the driver would.
fn walk_one(leg: &A2aLeg, kernel: &Kernel, body: &[u8]) -> Ended {
    use crate::root::transports::PlaneLeg as _;
    let facts: [(&str, &str); 3] = [
        ("path", "/a2a"),
        ("method", "POST"),
        ("peer", "127.0.0.1:1"),
    ];
    let chain: [&'static str; 2] = ["tcp", "http"];
    let arrival = busbar_contract::transport::Arrival {
        facts: &facts,
        body,
        transport: "http",
        chain: &chain,
        operation: None,
        bar: busbar_contract::transport::Bar::Open,
    };
    let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
        &kernel.admit_token(),
        busbar_caps::PrincipalId::new(""),
        0,
    ));
    let leases = busbar_kernel::slice::LeaseCell::new();
    let meter = busbar_kernel::teller::AccrualMeter::new();
    let gauge = busbar_kernel::slice::ConcurrencyGauge::new();
    let canary = busbar_caps::Canary::new();
    leg.walk(
        &arrival,
        kernel,
        &a_ctx(),
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    )
}

/// The step an ending refused at, where it refused.
fn refused_at(ended: &Ended) -> Option<busbar_caps::StepName> {
    match ended {
        Ended::Settled { end, .. } => match end.outcome() {
            busbar_caps::Outcome::Refused(step, _) | busbar_caps::Outcome::Failed(step, _) => {
                Some(step)
            }
            _ => None,
        },
        Ended::AlreadySettled => None,
    }
}

/// Whether an ending completed.
fn completed(ended: &Ended) -> bool {
    matches!(
        ended,
        Ended::Settled { end, .. } if matches!(end.outcome(), busbar_caps::Outcome::Completed)
    )
}
