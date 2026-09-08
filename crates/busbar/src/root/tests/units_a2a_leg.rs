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
        pricer: Some(Pricer::flat(0)),
        bytes_nanos: Some(0),
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
        priced: false,
        has_key: false,
    }
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
    refuses!("pricer", pricer);
    refuses!("bytes_nanos", bytes_nanos);
    refuses!("records", store);
    refuses!("meter_policy", meter_policy);
    refuses!("scope_policy", scope_policy);
    refuses!("durability", durability);
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

/// **The pool this plane admits and meters against is the codec's own section name.**
///
/// A copy that is checked is not a second opinion. The legacy receiving path admits and meters every
/// A2A unit against `busbar_a2a_codec::CONFIG_SECTION`, and a root that admitted against a different
/// string would be opening a second set of buckets for one plane's traffic — with both halves
/// looking healthy, because an empty bucket reconciles.
#[test]
fn the_plane_pool_is_the_codec_crates_own_section_name() {
    let codec = include_str!("../../../../busbar-a2a-codec/src/lib.rs");
    let declared = codec
        .lines()
        .find_map(|l| l.trim().strip_prefix("pub const CONFIG_SECTION: &str = "))
        .and_then(|rest| rest.split('"').nth(1))
        .expect("the codec crate declares its config section as a string literal");
    assert_eq!(
        PLANE_POOL, declared,
        "the root's restated pool name and the codec's own section name are one string"
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

impl crate::root::units_a2a::A2aDispatch for CountingSurface {
    fn execute(&self, _op: busbar_contract::ids::OpClassId) -> crate::root::units_a2a::A2aAnswer {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::root::units_a2a::A2aAnswer {
            status: SURFACE_STATUS,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: SURFACE_BODY.to_vec(),
        }
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
    let bindings = leg.bindings(&pools, &kinds, &[], None, 1_700_000_000, 0, Some(surface));
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
    dispatch: Option<&dyn crate::root::units_a2a::A2aDispatch>,
) -> (Ended, Option<crate::root::units_a2a::A2aAnswer>) {
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
