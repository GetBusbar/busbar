//! Tests for `units_mcp_leg.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::*;
use busbar_caps::{
    Canary, Hold, HoldCell, OriginKind, Outcome, PrincipalId, ReasonCode, StepName, UnitKey,
};
use busbar_contract::{
    ids::LaneId, ids::OpClassId, transport::facts::METHOD, transport::facts::PATH,
    transport::Arrival, transport::Bar,
};
use busbar_kernel::{
    registry::Generation, slice::ConcurrencyGauge, slice::LeaseCell, teller::AccrualMeter,
};
use busbar_unit_auth::AuthChain;
use busbar_unit_ledger::legacy::RecordingRows;
use busbar_unit_scope::required_scope;
use busbar_unit_trust::Unavailable;

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   EVERY BINDING HAS A SOURCE, AND THE TABLE IS CHECKED AGAINST THE STRUCT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// The `McpBindings` field names, read out of that struct's OWN SOURCE.
///
/// A source scan rather than a hand-kept list, because a hand-kept list is exactly the thing the
/// table is supposed to make impossible: the day someone adds a nineteenth binding, a hand-kept list
/// agrees with itself and the new field is bound to whatever the assembly happened to have.
fn bindings_fields() -> Vec<String> {
    let src = include_str!("../units_mcp.rs");
    let start = src
        .find("pub struct McpBindings<'r> {")
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
/// This is the finding's own acceptance test. `McpBindings` described one unit of this plane
/// precisely and completely and NOTHING in the workspace held the things it borrows: every
/// construction of it was a cell's, and a cell supplies whatever it likes. The table is the
/// accounting, and this cell is what keeps it honest in both directions — a field with no row fails,
/// and a row for a field that no longer exists fails too.
#[test]
fn every_binding_of_the_unit_has_a_row_in_the_source_table() {
    let fields = bindings_fields();
    assert_eq!(
        fields.len(),
        19,
        "the bindings carry nineteen halves; the table is written per field, so a change in the \
         count is a change this test has to see"
    );
    for field in &fields {
        assert!(
            SOURCES.iter().any(|(name, _)| name == field),
            "`McpBindings::{field}` has no row in the leg's field→source table: a binding with no \
             source is a control supplied by whoever happened to build the struct"
        );
    }
    for (name, where_) in SOURCES {
        assert!(
            fields.iter().any(|f| f == name),
            "the source table names `{name}`, which is not a field of `McpBindings` any more"
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

/// The registration every cell below is written against.
static ONE_SERVER: &[busbar_plane_mcp::Server] = &[busbar_plane_mcp::Server {
    id: "fs",
    lane: LaneId::new("fs-lane"),
    host: "127.0.0.1:9",
    transport: claims::TRANSPORT_HTTP,
}];

/// A kernel to lend the sealed origin from.
fn a_kernel() -> Kernel {
    Kernel::new()
}

/// A breaker that benches nothing, so a cell about assembly is not also a cell about readiness.
struct EveryLaneOpen;

impl BreakerView for EveryLaneOpen {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(&self, _pool: &str, _lane: usize, _now: u64) -> Result<(), Unavailable> {
        Ok(())
    }
}

/// Every source present, so a cell can take one away and watch the assembly refuse.
fn all_sources(kernel: &Kernel) -> McpLegSources<'_> {
    McpLegSources {
        plane: McpPlane::new(ONE_SERVER),
        kernel,
        auth: Some(Auth::new(AuthChain::new(Vec::new(), false))),
        auth_bindings: Some(AuthBindings::without_directory()),
        breaker: Some(Arc::new(EveryLaneOpen)),
        guard: Some(GuardPolicy {
            allow_private: true,
            ..GuardPolicy::default()
        }),
        denylist: Some(Denylist::default()),
        door: Some(Door::new(InMemoryCells::new())),
        groups: Some(GroupTable::default()),
        pricer: Some(Pricer::flat(0)),
        store: Some(crate::root::mount_ingress::tests::memory_store()),
        meter_policy: Some(crate::root::policy::build(
            &crate::root::policy::MeterPolicyConfig::default(),
        )),
        scope_policy: Some(McpLeg::scope_policy(ScopePolicy::new())),
        durability: Some(Arc::new(Mutex::new(
            crate::root::durability::build(
                &crate::root::durability::DurabilityConfig { data_dir: None },
                Box::new(busbar_unit_wal::NullShipper::new()),
                Box::new(RecordingRows::new()),
            )
            .expect("a memory-buffered journal cannot fail to open"),
        ))),
        key_scopes: None,
        priced: true,
        has_key: true,
        catalogue: Vec::new(),
    }
}

/// **A source the deployment does not have refuses BOOT, and the refusal names the field.**
///
/// RED FIRST, and the red is the reason this is a refusal rather than a default. Every one of these
/// fields has a "harmless" default sitting right there: an empty auth chain, an empty group table,
/// an empty denylist. Every one of those defaults BOOTS CLEAN AND SERVES TRAFFIC — an empty chain
/// admits anonymously, an empty group table says yes to every cap, an empty denylist guards nothing
/// — and none of them has a failing test of its own, because an absent control refuses nothing and
/// therefore breaks nothing. So the assembly refuses, and it says which one.
#[test]
fn a_binding_with_no_source_refuses_boot_naming_the_field() {
    let kernel = a_kernel();

    macro_rules! refuses {
        ($field:expr, $take:ident) => {{
            let mut sources = all_sources(&kernel);
            sources.$take = None;
            let refusal = McpLeg::assemble(sources).err().unwrap_or_else(|| {
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
    // The guard policy and the denylist are two halves of ONE binding — the per-kind facts the
    // trust unit reads — so both name it. A refusal that named a field `McpBindings` does not have
    // would send an operator looking for a value the struct never carried.
    refuses!("kinds", guard);
    refuses!("kinds", denylist);
    refuses!("door", door);
    refuses!("chain", groups);
    refuses!("pricer", pricer);
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
        McpLeg::assemble(all_sources(&kernel)).is_ok(),
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
    sources.durability = None;
    let refusal = McpLeg::assemble(sources).expect_err("the book has no source");
    let row = SOURCES
        .iter()
        .find(|(name, _)| *name == "durability")
        .expect("the table has a row for it");
    assert_eq!(
        refusal.source, row.1,
        "the refusal's words are the table's own row"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE MONEY IS READ LIVE, NEVER CAPTURED AT BOOT
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **The leg keeps no class price, and it reads them off the process's live card.**
///
/// A structural proof rather than a behavioural one, and deliberately: the card holder is a process
/// global, so a cell that swapped a card to watch a figure move would be a cell every other cell in
/// this binary races against. What can be said without racing anything is the thing that actually
/// matters — that there is nowhere on this leg for a boot reading of the RATES to be KEPT, and that
/// the one place they are read names the holder.
///
/// A leg that captured them at boot would go on pricing this node's ledger against rates the
/// operator has already replaced: the usage projection reprices on an apply and the ledger would
/// not, and the identity that says the two are one money would hold only until the first rate moved.
///
/// **THE FLAT FEE IS THE STATED EXCEPTION.** It is a `Pricer` the caller resolved, held on the leg,
/// because the fee lives behind the cost unit's own field and the construction gate names the two
/// crates entitled to read it — a composition root deriving a pricer from it would be a third. So
/// the fee this leg prices with is the one resolved when the leg was assembled, exactly as the A2A
/// sibling's is, and this cell asserts the exception is the ONLY one.
#[test]
fn the_leg_keeps_no_captured_rate_and_reads_the_live_card() {
    let src = include_str!("../units_mcp_leg.rs");
    let start = src
        .find("pub struct McpLeg {")
        .expect("the leg struct is in this file");
    let body = &src[start..start + src[start..].find("\n}\n").expect("it closes")];
    for kept in ["prices:", "bytes_nanos:", "fee_nanos:", "tool_calls:"] {
        assert!(
            !body.contains(kept),
            "`McpLeg` keeps `{kept}` — a rate held on the leg is a rate read once at boot, and an \
             apply after that moves the projection and not this node's books"
        );
    }
    assert!(
        body.contains("pricer: Pricer,"),
        "the flat fee IS held, and it is held as a value the caller resolved rather than one this \
         leg derived — a change that made the leg derive it would be a third crate reading a field \
         the gate says two may read, and this cell is where that shows up"
    );
    let prices = src
        .find("fn prices(&self, arrived_ms: u64)")
        .map(|at| &src[at..at + 900])
        .expect("the one reading of the rates is written here");
    assert!(
        prices.contains("ROOT_CARD.pin()") && prices.contains("card_at(arrived_ms)"),
        "the rates come off the process's own rate-card history, which the rate-apply seam appends \
         to on boot AND on every live apply or reload, resolved at the instant the unit arrived"
    );
    assert!(
        prices.contains("lane_rates") && prices.contains("nanos_per_unit"),
        "and the readings are the card's own published ones, over the registration's own lane — no \
         class-keyed table is invented and no configuration key is added"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE LEG ON THE LOOP
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// One arrival, as a mount publishes it: the reserved facts, the body, and the composed stack.
fn arrival_at<'a>(facts: &'a [(&'static str, &'a str)], body: &'a [u8]) -> Arrival<'a> {
    static CHAIN: [&str; 2] = ["tcp", "http"];
    Arrival {
        facts,
        body,
        transport: claims::TRANSPORT_HTTP,
        chain: &CHAIN,
        // The address named no operation: this is a MOUNT, and which operation these bytes are is
        // the plane's to say off the document.
        operation: None,
        bar: Bar::Open,
    }
}

/// The facts an ordinary request on this plane's mount publishes.
fn mounted_facts() -> Vec<(&'static str, &'static str)> {
    vec![
        (PATH, claims::DEFAULT_MOUNT),
        (METHOD, "POST"),
        ("peer", "127.0.0.1:1"),
    ]
}

/// The surface the mount composes, counting what the loop asked it.
#[derive(Default)]
struct CountingSurface {
    asked: std::sync::atomic::AtomicUsize,
}

impl CountingSurface {
    fn asked(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// The bytes this double answers with, named so `execute` and `collect` cannot disagree about them.
const SURFACE_BODY: &[u8] = br#"{"jsonrpc":"2.0","id":1,"result":{"from":"the surface"}}"#;

impl crate::root::transports::MountDispatch for CountingSurface {
    fn execute(&self, _op: OpClassId) -> crate::root::transports::MountedReply {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        axum::http::Response::builder()
            .status(200)
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

/// Walk one body through the leg with the seam the mount composes, and take back both halves.
fn serve(
    leg: &McpLeg,
    kernel: &Kernel,
    body: &[u8],
    dispatch: Option<&dyn crate::root::transports::MountDispatch>,
) -> (Ended, Option<crate::root::transports::PlaneAnswer>) {
    let facts = mounted_facts();
    let cell = HoldCell::new(Hold::open(&kernel.admit_token(), PrincipalId::new(""), 0));
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let ctx = UnitCtx {
        key: UnitKey::new(1),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    leg.serve(
        &arrival_at(&facts, body),
        kernel,
        &ctx,
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

/// **The leg produces one unit per arrival, and it walks.**
///
/// RED FIRST: `McpBindings` borrows things nothing in the workspace held, so there was no way to
/// build one outside a cell — which is the same sentence as "this plane's decode reaches no step of
/// the kernel". What this asserts is the whole of the leg's job: the plane read the bytes, the loop
/// ran over what it said, and the surface's own answer came back out.
#[test]
fn the_leg_walks_one_arrival_through_the_loop_and_the_surfaces_answer_comes_back() {
    let kernel = a_kernel();
    let leg = McpLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let surface = CountingSurface::default();
    let (ended, answer) = serve(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        Some(&surface),
    );

    let Ended::Settled { end, .. } = &ended else {
        panic!("the unit settled here: {ended:?}");
    };
    assert_eq!(
        end.outcome(),
        Outcome::Completed,
        "every one of the twelve answered"
    );
    assert_eq!(surface.asked(), 1, "the surface is asked exactly once");
    assert_eq!(
        answer.map(|a| a.status),
        Some(200),
        "and its whole answer comes back out"
    );
}

/// **A method this plane cannot name never reaches the surface**, and the leg says so before the
/// loop is entered.
///
/// Two readings of one fact, and both matter to a mount: `recognises` is what lets it hand such a
/// request straight to the router that already answers it with the `-32601` release pinned, and the
/// walk is what happens if it does not — a refusal at the step that read the bytes, with the surface
/// untouched either way.
#[test]
fn a_body_this_plane_cannot_name_is_recognised_as_not_ours_and_never_executed() {
    let kernel = a_kernel();
    let leg = McpLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let facts = mounted_facts();

    assert!(
        leg.recognises(&arrival_at(
            &facts,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#
        )),
        "a method the plane's own table names is a unit of this plane"
    );
    assert!(
        !leg.recognises(&arrival_at(
            &facts,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/obliterate"}"#
        )),
        "and one it does not name is a request the mounted router already answers"
    );

    let surface = CountingSurface::default();
    let (ended, answer) = serve(
        &leg,
        &kernel,
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/obliterate"}"#,
        Some(&surface),
    );
    let Ended::Settled { end, .. } = &ended else {
        panic!("a refused unit still settles: {ended:?}");
    };
    assert_eq!(
        end.outcome(),
        Outcome::Refused(StepName::Decode, ReasonCode::DecodeFailed)
    );
    assert_eq!(surface.asked(), 0);
    assert!(answer.is_none());
}

/// **The driven path has no seam**, which is the posture a build with no mount has.
///
/// `PlaneLeg::walk` is the same walk with the seam absent and the answer dropped — one body, not
/// two, because a second assembly of the bindings would be a second chance for a mounted unit and a
/// driven one to be judged differently.
#[test]
fn the_driven_path_runs_the_same_twelve_and_produces_no_bytes() {
    use crate::root::transports::PlaneLeg as _;

    let kernel = a_kernel();
    let leg = McpLeg::assemble(all_sources(&kernel)).expect("every source is present");
    let facts = mounted_facts();
    let cell = HoldCell::new(Hold::open(&kernel.admit_token(), PrincipalId::new(""), 0));
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let ctx = UnitCtx {
        key: UnitKey::new(1),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let ended = leg.walk(
        &arrival_at(&facts, br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
        &kernel,
        &ctx,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
        },
    );
    let Ended::Settled { end, frame, .. } = &ended else {
        panic!("the unit settled here: {ended:?}");
    };
    assert_eq!(end.outcome(), Outcome::Completed);
    assert!(
        frame.as_ref().is_none_or(|f| f.bytes.as_slice().is_empty()),
        "no surface behind the walk, so nothing was written"
    );
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
//   THE OPEN SURFACE STAYS OPEN
// ═════════════════════════════════════════════════════════════════════════════════════════════════

/// **The discovery document declares no scheme, and the request surface on the same carrier does.**
///
/// The question a leg must not answer by carrier alone. Both claims are made over the document
/// transport and only one of them carries a credential — so a leg that read "http means bearer"
/// would demand a token on the one surface a caller reads in order to find out how to get one.
#[test]
fn the_scheme_is_a_question_about_the_address_and_not_only_the_carrier() {
    assert!(
        claims::declares_scheme(claims::TRANSPORT_HTTP, claims::DEFAULT_MOUNT),
        "the request surface carries a credential"
    );
    assert!(
        !claims::declares_scheme(claims::TRANSPORT_HTTP, claims::DEFAULT_METADATA),
        "and the discovery document deliberately does not"
    );
    assert!(
        !claims::declares_scheme(claims::TRANSPORT_HTTP, "/mcpx"),
        "and an address no claim of this plane matches declares nothing"
    );
}

/// **The pool the leg admits and meters against is the registration's own key.**
///
/// `tool:<name>`, which is the key the breaker and the pool table already use. A leg that admitted
/// against a different string would open a second set of buckets for one plane's traffic, with both
/// halves looking healthy because an empty bucket reconciles.
#[test]
fn the_pool_is_the_registrations_own_key() {
    let kernel = a_kernel();
    let leg = McpLeg::assemble(all_sources(&kernel)).expect("every source is present");
    assert_eq!(leg.pool(), pool_key("fs"));
}

/// **The scope policy the leg declares covers every class the plane declares.**
///
/// The scope unit reads silence as a refusal, so a plane with a partly-declared policy is a plane
/// whose remaining operations are unreachable for a reason nobody can find in a configuration file.
#[test]
fn the_leg_declares_a_scope_for_every_class_the_plane_has() {
    let policy = McpLeg::scope_policy(ScopePolicy::new());
    assert_eq!(
        policy.len(),
        declared_classes().len(),
        "one entry per declared operation class, neither more nor fewer"
    );
    for op in answered_classes() {
        assert!(
            required_scope(claim_key(), *op, &policy).is_some(),
            "{op} is a class this plane says it ANSWERS, and the policy is silent about it"
        );
    }
}

/// **The catalogue is a source the assembly takes whole**, and the leg reports how many rows it
/// composes from — which is the figure the boot line prints, so a rig reading that line is reading
/// the mounted leg's own count and not the legacy router's.
#[test]
fn the_leg_holds_the_catalogue_rows_it_was_assembled_with() {
    let kernel = a_kernel();
    let mut sources = all_sources(&kernel);
    sources.catalogue = vec![busbar_plane_mcp::catalogue::Row {
        kind: busbar_plane_mcp::catalogue::RowKind::Tool,
        server: "fs".to_string(),
        name: "fs_grep".to_string(),
        wire: serde_json::json!({ "name": "fs_grep" }),
    }];
    let leg = McpLeg::assemble(sources).expect("every source is present");
    assert_eq!(leg.catalogue_len(), 1);
    assert_eq!(
        McpLeg::assemble(all_sources(&kernel))
            .expect("every source is present")
            .catalogue_len(),
        0,
        "an empty catalogue is a deployment with no `tools:` block, not a missing source"
    );
}
