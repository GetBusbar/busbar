//! Tests for `units_voice.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_caps::Canary;
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit, Ended, Kernel, Run};
use busbar_unit_auth::AuthChain;

const REALTIME: LaneId = LaneId::new("voice-realtime");
const LIVE: LaneId = LaneId::new("voice-live");

/// The two composed provider endpoints, as a node's registry would hold them.
static UPSTREAMS: &[Upstream] = &[
    Upstream {
        lane: REALTIME,
        host: "api.openai.com",
        dialect: Dialect::OpenaiRealtime,
    },
    Upstream {
        lane: LIVE,
        host: "generativelanguage.googleapis.com",
        dialect: Dialect::GeminiLive,
    },
];

/// THE CLASS THE ROOT NAMES IS THE CLASS THE PLANE DECLARES, at every site that names it.
///
/// The label selects the unit price, so a turn admitted against one spelling and settled under
/// another is money on a rate card where the two rates differ — and a wire string re-spelled in
/// the root is a rename in the plane that leaves the root pricing under a class nobody declares.
/// The plane's declaration is the one source, and every reading below comes from it.
#[test]
fn the_emitted_audio_class_is_the_one_the_plane_declares() {
    let declared = <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES
        .iter()
        .any(|class| class.key == meta::CLASS_AUDIO_TOKENS_OUT);
    assert!(
        declared,
        "the plane declares the class the root prices under"
    );

    let usage = TurnUsage {
        audio_tokens_out: 3,
        ..TurnUsage::default()
    };
    let line = usage
        .lines()
        .into_iter()
        .find(|line| line.quantity == 3)
        .expect("the emitted audio is reported");
    assert_eq!(line.class, meta::CLASS_AUDIO_TOKENS_OUT);
    // And the one spelling is still the released one: a shared constant makes a rename cheap,
    // which is exactly why the wire string it carries is pinned here.
    assert_eq!(line.class.as_str(), "audio_tokens_out");
}

/// EVERY class the plane declares is a class the root knows what to put in, and the root emits
/// none the plane does not declare.
///
/// This is the assertion that turns a rename from a silent mispricing into a red build. The root
/// no longer keeps its own list of class names — it walks the plane's declaration and asks what
/// each entry is worth — so a class the plane renames stops being recognised, produces no line,
/// and is caught here. Without this, that class would simply stop being reported, and a class
/// that is not reported settles at nothing on every turn of every session.
#[test]
fn every_declared_class_carries_a_figure() {
    // A turn that carried something under all seven, so the only reason a class can be missing
    // from the report below is that the root did not recognise it.
    let usage = TurnUsage {
        audio_tokens_in: 11,
        audio_tokens_out: 12,
        text_tokens_in: 13,
        text_tokens_out: 14,
        cached_tokens: 15,
        audio_ms_in: 16_000,
        tool_calls: 17,
    };
    let lines = usage.lines();
    let declared = <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES;
    assert_eq!(
        lines.len(),
        declared.len(),
        "one line per declared class, and no line the plane did not declare"
    );
    for decl in declared {
        assert!(
            lines.iter().any(|line| line.class == decl.key),
            "the root has a figure for every class the plane declares"
        );
    }
    // And the sum the lease and the exit evidence both read is the sum of exactly those lines.
    assert_eq!(
        usage.total(),
        lines.iter().map(|line| line.quantity).sum::<u64>()
    );
}

/// A dial that opens, so a cell can reach the stations past route without an I/O half.
struct OpenDial;
impl ProviderDial for OpenDial {
    fn dial(&self, _target: &DialTarget) -> Result<(), DialRefusal> {
        Ok(())
    }
}

/// A lease that can be taken and never runs dry.
struct OpenLease;
impl SessionLease for OpenLease {
    fn reserve(&self, _session: u64, _nanos: u64) -> Result<(), ReasonCode> {
        Ok(())
    }
    fn settle(&self, _session: u64, _nanos: u64) -> bool {
        true
    }
    fn close(&self, _session: u64) {}
}

fn node(io: VoiceIo) -> VoiceNode {
    // A deployment that configured no group: every caller is attributed and none is capped.
    node_governed_by(io, busbar_unit_admission::GroupTable::default())
}

fn node_governed_by(io: VoiceIo, groups: busbar_unit_admission::GroupTable) -> VoiceNode {
    node_behind(
        io,
        groups,
        // The chain these tests run is the empty one — the open front door — so the seams have
        // nothing to answer and the unbound posture is the honest fixture for them.
        Auth::new(AuthChain::new(Vec::new(), false)),
        crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
    )
}

/// The same node behind a door a deployment actually shut.
///
/// Split out of `node` rather than duplicated because the only thing an authenticate cell may
/// vary is the door: a fixture that also swapped the pricer, the scope table or the journal
/// would be asserting about a different node than every other cell in this file.
fn node_behind(
    io: VoiceIo,
    groups: busbar_unit_admission::GroupTable,
    auth: Auth,
    auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
) -> VoiceNode {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    VoiceNode::new(VoiceNodeParts {
        plane: VoicePlane::new(UPSTREAMS),
        groups,
        pricer: Pricer::flat(0),
        auth,
        auth_bindings,
        scope: scope_policy(),
        meter_policy: crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        durability,
        io,
        origin: Kernel::new().origin(busbar_caps::OriginKind::Client),
    })
}

fn serviceable() -> VoiceIo {
    VoiceIo {
        dial: Box::new(OpenDial),
        lease: Box::new(OpenLease),
        ..VoiceIo::default()
    }
}

/// The chain a deployment with no `groups:` section resolves for every caller: one uncapped
/// attribution bucket, charged on every admission and blocking nothing.
///
/// One value for the whole test module, because it is one value for the whole node — which is
/// the property the unit's borrow exists to make visible.
fn ungoverned() -> &'static busbar_unit_admission::BucketChain {
    static CHAIN: std::sync::OnceLock<busbar_unit_admission::BucketChain> =
        std::sync::OnceLock::new();
    CHAIN.get_or_init(|| {
        busbar_unit_admission::GroupTable::default()
            .chain_for("acct:voice", None)
            .expect("a caller bound to no group always resolves")
    })
}

fn ctx(key: u64) -> UnitCtx {
    UnitCtx {
        key: busbar_caps::UnitKey::new(key),
        origin: busbar_caps::OriginKind::Client,
        session: Some(Kernel::new().session_id(7)),
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

fn run(kernel: &Kernel, unit: &VoiceUnit<'_>) -> Ended {
    let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
        &kernel.admit_token(),
        PrincipalId::new("acct:voice"),
        0,
    ));
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    run_unit(
        kernel,
        unit,
        &ctx(1),
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

/// The whole session-bound path, as one unit: the connection arrives over a composed transport,
/// the handshake runs every station, the lease is taken at the door, the provider leg opens, and
/// the unit settles once. That last word is the assertion — `Settled` is the exit path having
/// taken the hold, and there is no second taker in this run.
#[test]
fn unit_zero_runs_every_station_and_settles_exactly_once() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let ended = run(&kernel, &unit);
    assert!(matches!(ended, Ended::Settled { .. }));
    assert_eq!(unit.dial_outcome(), Some(Ok(())));
}

/// A CREDENTIAL THE NODE'S OWN DOOR DOES NOT ACCEPT ENDS THE SESSION AT THE AUTHENTICATE STEP,
/// and the audience is the thing that decides it.
///
/// Authenticate is a gating step, and until this cell existed nothing drove one over the loop on
/// this plane: the conformance rig's credential leg proves the credential the node dials OUT
/// under, which is the other direction entirely. A plane that ships through the composition root
/// with its inbound credential check driven by nobody is a door whose lock has never been turned.
///
/// The audience is where the turn happens. Every one of this plane's credentialed claims carries
/// one, so a token minted for a SIBLING plane's audience is a well-formed, unexpired, correctly
/// signed token — and must still be refused here, at the plane boundary, rather than at whatever
/// it was going to reach. That is the shape a wrong-audience token has to be refused in for the
/// audience to be a boundary rather than a decoration.
///
/// The accepted control runs beside it, because a door that refuses everything is not a door: the
/// same directory, the same chain, the plane's own audience, and the unit runs to its end.
#[test]
fn a_credential_the_door_does_not_accept_ends_the_session_at_authenticate() {
    use crate::root::kernel::auth_bindings::AuthBindings;
    use busbar_contract::{KeyFacts, VirtualKeyDirectory};

    /// One issued key, accepted only under the audience this plane declares — and a record of
    /// the audience it was asked under, so the boundary is measured and not merely stated.
    #[derive(Default)]
    struct OneKey {
        asked_under: Mutex<Vec<Option<String>>>,
    }

    impl VirtualKeyDirectory for OneKey {
        fn operator_token_hash(&self) -> Option<String> {
            None
        }

        fn verify(
            &self,
            credential: &str,
            _now: u64,
            expected_aud: Option<&str>,
        ) -> Option<KeyFacts> {
            self.asked_under
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(expected_aud.map(str::to_string));
            (credential == "tok"
                && expected_aud == Some(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY))
            .then(|| KeyFacts {
                id: "key-voice-1".to_string(),
                name: "an approved key".to_string(),
                scopes: None,
                enabled: true,
                expires_at: None,
                deleted_at: None,
            })
        }

        fn is_revoked(&self, _credential: &str) -> bool {
            false
        }
    }

    // A chain naming the signed-key arm and no boxed module: the front door is SHUT, and the arm
    // is the one thing that can open it — which is what makes this cell about the arm.
    let shut = || Auth::new(AuthChain::new(Vec::new(), true));
    assert!(!shut().chain().is_open());

    // ONE directory across all three runs, so what it was asked can be read at the end.
    let directory = std::sync::Arc::new(OneKey::default());
    let kernel = Kernel::new();
    let door = |credential: Option<&str>| -> Outcome {
        let node = node_behind(
            serviceable(),
            busbar_unit_admission::GroupTable::default(),
            shut(),
            AuthBindings::new(std::sync::Arc::clone(&directory) as _),
        );
        let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        let unit = match credential {
            Some(c) => unit.with_credential(c),
            None => unit,
        };
        let Ended::Settled { end, .. } = run(&kernel, &unit) else {
            panic!("a refused unit settles through the same exit");
        };
        let outcome = end.outcome();
        if matches!(outcome, Outcome::Refused(_, _)) {
            // Read while the node is still alive: a unit refused at the door must not have
            // dialed, and the dial is the first thing a half-opened session would show.
            assert_eq!(
                unit.dial_outcome(),
                None,
                "a session refused at authenticate never reaches the provider"
            );
        }
        outcome
    };

    // A token this node's directory never issued, and no token at all — the two shapes an
    // unauthenticated open arrives in.
    for presented in [Some("nope"), None] {
        let outcome = door(presented);
        assert!(
            matches!(
                outcome,
                Outcome::Refused(
                    busbar_caps::StepName::Authenticate,
                    ReasonCode::Unauthenticated
                )
            ),
            "presented {presented:?}, got {outcome:?}"
        );
    }

    // THE CONTROL: the key the directory did issue. A door that refuses everything is not a
    // door, and a refusal cell without one proves only that nothing gets in.
    let outcome = door(Some("tok"));
    assert!(
        matches!(outcome, Outcome::Completed),
        "the accepted credential runs the session to its end, got {outcome:?}"
    );

    // AND THE AUDIENCE IS THE PLANE'S OWN, every time it was asked. The expected audience is
    // what makes a sibling plane's well-formed token refusable HERE rather than at whatever it
    // was going to reach — a root that passed `None` would verify signatures and check no
    // boundary, and every assertion above would still read the same.
    let asked = directory
        .asked_under
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert!(!asked.is_empty(), "the arm was reached at all");
    for aud in asked.iter() {
        assert_eq!(
            aud.as_deref(),
            Some(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY)
        );
    }
}

/// The alternatives the authenticate step offers the auth unit are the ones the claim declared.
///
/// The unit refuses a narrowing OUTSIDE the declared set before it looks at a credential, so a
/// root that offered a smaller set than the claims declare would refuse a caller the deployment
/// meant to admit, and one that offered a larger set would let the plane pick a scheme no claim
/// ever made.
#[test]
fn the_declared_alternatives_are_the_claims_own() {
    assert_eq!(SESSION_SCHEME_ALTERNATIVES, &["bearer", "api-key"]);
}

/// The grant a caller holds is compared against what the class requires, and a caller who holds
/// less is refused.
///
/// The step used to stop one line short: it found the required scope and then proceeded on
/// having FOUND it, which authorizes every principal for every class a deployment did name and
/// refuses only the classes it forgot. On this plane every governed class requires the full
/// grant, so a read-only credential reached a turn — the priced operation — on the strength of a
/// lookup that never compared anything.
///
/// The handshake arm is asserted beside it because it is the one thing that must NOT change: a
/// kernel-granted operation is answered before the policy is asked, which is what lets a node
/// hand shake before it has authenticated anybody.
#[test]
fn a_caller_who_holds_less_than_the_class_requires_is_refused() {
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let node = node(serviceable());

    let decide = |shape: UnitShape, held: Grants| -> bool {
        let unit = VoiceUnit::new(&node, shape, 7, 1_700_000_000).holding(held);
        let token: UnitToken<busbar_caps::step::Approve> = UnitToken::mint(&seal);
        unit.approve(&token, &ctx(1), &PrincipalId::new("acct:voice"), &[])
            .into_result(&seal)
            .is_ok()
    };

    assert!(
        !decide(UnitShape::Turn, Grants::of(Scope::ReadOnly)),
        "a read-only credential reached a turn, which the plane declares as full"
    );
    assert!(
        !decide(UnitShape::ToolCall, Grants::of(Scope::ReadOnly)),
        "a read-only credential reached a tool call"
    );
    assert!(
        decide(UnitShape::Turn, Grants::of(Scope::Full)),
        "a full credential was refused the operation it holds the grant for"
    );
    assert!(
        decide(UnitShape::SessionOpen, Grants::of(Scope::ReadOnly)),
        "the handshake stopped being kernel-granted"
    );
}

/// A handshake POSTS nothing and draws no request slot — which is what lets a node hand shake
/// before it has authenticated anybody without the shaking taking a caller's concurrency. No
/// class of usage passes through unit zero, so the amount it settles is zero.
///
/// What it DOES draw is the session's one flat fee, which is a count and not a posting: opening
/// the session is the billable arrival, and every frame after it is the conversation that
/// arrival paid for.
#[test]
fn the_handshake_draws_no_request_slot_and_posts_nothing() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let Ended::Settled { requests, fee, end } = run(&kernel, &unit) else {
        panic!("the exit path settles a handshake like anything else");
    };
    assert_eq!(requests, 0, "a handshake reaches no upstream candidate");
    assert_eq!(fee, 1, "the session's one flat fee is drawn where it opens");
    assert!(matches!(end.outcome(), Outcome::Completed));
    assert_eq!(
        end.into_posted().expect("the report fits").settled(),
        0,
        "and it meters nothing: no class of usage passes through unit zero"
    );
}

/// A node with no I/O half cannot open a session, and says so at the door rather than opening one
/// that cannot pay. The reservation IS the budget: a lease that could not be taken must not read
/// as one that was.
#[test]
fn a_detached_node_refuses_the_session_at_the_door() {
    let kernel = Kernel::new();
    let node = node(VoiceIo::default());
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let Ended::Settled { end, .. } = run(&kernel, &unit) else {
        panic!("a refused unit settles through the same exit");
    };
    assert_eq!(
        end.outcome(),
        Outcome::Refused(
            busbar_caps::StepName::Admit,
            ReasonCode::DurabilityUnavailable
        ),
        "a node with no I/O half must be refused at admit, under the node's own unavailability \
         reason - not reported as an over-budget principal, and not any other refusal in the \
         vocabulary"
    );
    assert_eq!(
        unit.dial_outcome(),
        None,
        "a unit refused at the door never reaches the dial"
    );
}

/// A guard-refused or breaker-open dial ends the opening unit rather than half-opening a session.
/// The dial is the handshake's route leg, so its refusal is the unit's ending, and the session
/// the unit would have created does not exist.
#[test]
fn a_refused_dial_ends_the_opening_unit() {
    struct Guarded;
    impl ProviderDial for Guarded {
        fn dial(&self, _target: &DialTarget) -> Result<(), DialRefusal> {
            Err(DialRefusal::GuardRefused)
        }
    }
    let kernel = Kernel::new();
    let node = node(VoiceIo {
        dial: Box::new(Guarded),
        lease: Box::new(OpenLease),
        ..VoiceIo::default()
    });
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let Ended::Settled { end, .. } = run(&kernel, &unit) else {
        panic!("the exit settles it");
    };
    // **Past the door it is a failure, not a refusal, and the difference is the money.** A unit
    // stopped before admission was never charged and ends `Refused`; this one was admitted, so
    // whatever it spent is real and the ending has to say the unit ran and did not get there.
    // The loop draws that line itself — the step's decision was a refusal either way — which is
    // why this cell asserts the loop's answer rather than the step's.
    assert!(
        matches!(
            end.outcome(),
            Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::NoDestination)
        ),
        "got {:?}",
        end.outcome()
    );
    assert_eq!(unit.dial_outcome(), Some(Err(DialRefusal::GuardRefused)));
}

/// A turn is the governed transaction, and what it reports is what it settles against. The two
/// text halves land on their own classes: summed into one, the emitted half would price at the
/// input rate, which is a money question and not a spelling one.
#[test]
fn a_turn_meters_the_classes_the_plane_declares_with_text_split_by_direction() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .on_dialect(Dialect::OpenaiRealtime)
        .reporting(TurnUsage {
            audio_tokens_in: 10,
            audio_tokens_out: 20,
            text_tokens_in: 3,
            text_tokens_out: 4,
            cached_tokens: 1,
            audio_ms_in: 640,
            tool_calls: 2,
        });
    let lines = unit.usage.lines();
    let quantity = |class: &str| {
        lines
            .iter()
            .find(|l| l.class.as_str() == class)
            .map(|l| l.quantity)
    };
    assert_eq!(quantity("text_tokens_in"), Some(3));
    assert_eq!(quantity("text_tokens_out"), Some(4));
    // 640 ms of admitted audio is one second on a seconds-denominated class, not 640 of them.
    assert_eq!(quantity("audio_seconds_in"), Some(1));
    assert_eq!(quantity("tool_calls"), Some(2));

    let ended = run(&kernel, &unit);
    assert!(matches!(ended, Ended::Settled { .. }));
}

/// The two quantities this plane derives itself are marked as what they are. A figure the
/// destination confirmed and one the node counted are not the same evidence, and the whole point
/// of carrying the source with the quantity is that a dispute turns on exactly that difference.
#[test]
fn the_derived_quantities_are_marked_estimated_and_the_reported_ones_are_not() {
    let usage = TurnUsage {
        audio_tokens_in: 10,
        audio_ms_in: 640,
        ..TurnUsage::default()
    };
    let lines = usage.lines();
    let estimated = |class: &str| {
        lines
            .iter()
            .find(|l| l.class.as_str() == class)
            .map(|l| l.estimated)
    };
    assert_eq!(estimated("audio_tokens_in"), Some(false));
    assert_eq!(estimated("audio_seconds_in"), Some(true));
}

/// A class with nothing to report produces no line. A zero line and an absent line settle the
/// same, but only one of them claims the upstream said so.
#[test]
fn a_class_with_nothing_to_report_produces_no_line() {
    assert!(TurnUsage::default().lines().is_empty());
}

/// The policy is asked about every class the plane declares, and it is asked rather than assumed:
/// a pair the policy says nothing about answers `None`, and `None` is a refusal.
#[test]
fn silence_in_the_scope_policy_is_a_refusal() {
    use busbar_unit_scope::PolicyView;
    let claim = ClaimKey::new(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY);
    let policy = scope_policy();
    assert!(policy
        .required_scope(claim, OpClassId::new(OP_DUPLEX_TURN))
        .is_some());
    assert!(
        policy
            .required_scope(claim, OpClassId::new("a-class-nobody-declared"))
            .is_none(),
        "a class the policy was never told about must not answer"
    );
}

/// A turn on an undeclared operation class is refused at approve, not admitted and charged. This
/// is the same finding as the one above, driven through the loop rather than asserted at the
/// table: authorization by omission is what the empty answer exists to prevent.
#[test]
fn an_undeclared_operation_class_is_refused_before_the_door() {
    let kernel = Kernel::new();
    let mut node = node(serviceable());
    node.scope = crate::root::policy::ScopePolicy::new();
    let unit =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    let Ended::Settled { end, requests, .. } = run(&kernel, &unit) else {
        panic!("the exit settles it");
    };
    assert_eq!(
        end.outcome(),
        Outcome::Refused(busbar_caps::StepName::Approve, ReasonCode::ScopeDenied),
        "an operation class the policy was never told about must be refused at approve, under \
         the scope-denied reason, not any other refusal in the vocabulary"
    );
    assert_eq!(requests, 0, "a unit refused before the door draws nothing");
}

/// The composed transport, recorded as composed. A voice session arrives on WebSocket, which is
/// only serviceable built over HTTP, and the chain names both — the under-reported chain of one
/// is the shape composition exists to fix.
#[test]
fn the_arrival_chain_records_both_composed_layers() {
    let node = node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    assert_eq!(unit.arrival.transport_chain, vec!["http", "ws"]);
}

/// Both composed provider endpoints are reachable by their own dialect, and neither is reachable
/// by the other's. A session that arrived speaking one wire dialing the other's endpoint would be
/// a session speaking to a server that cannot parse it.
#[test]
fn each_dialect_dials_its_own_composed_endpoint() {
    let node = node(serviceable());
    let realtime = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 0);
    assert_eq!(
        realtime.target().map(|t| t.url),
        Some("wss://api.openai.com".to_string())
    );
    let live = VoiceUnit::new(&node, UnitShape::SessionOpen, 8, 0).on_dialect(Dialect::GeminiLive);
    assert_eq!(
        live.target().map(|t| t.url),
        Some("wss://generativelanguage.googleapis.com".to_string())
    );
}

/// The dial posture is the fail-closed one, and it is not a per-dial choice. A root that widened
/// it for one endpoint would be a root deciding a question the trust unit owns.
#[test]
fn every_dial_takes_the_fail_closed_guard_posture() {
    let node = node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 0);
    let target = unit.target().expect("an endpoint is configured");
    assert_eq!(target.policy, GuardPolicy::default());
    assert!(
        !target.policy.plaintext_admissible(),
        "the default posture does not admit plaintext"
    );
}

/// The endpoints compose from names, and the names are borrowed for the life of the program. A
/// per-dial allocation of an endpoint name would be a leak the fixed-memory term cannot account
/// for, which is why the constructor cannot take an owned string.
#[test]
fn the_two_endpoints_compose_from_borrowed_names() {
    let endpoints = ProviderEndpoints::new(
        "api.openai.com",
        REALTIME,
        "generativelanguage.googleapis.com",
        LIVE,
    );
    let pair = endpoints.as_slice();
    assert_eq!(pair[0].dialect, Dialect::OpenaiRealtime);
    assert_eq!(pair[1].dialect, Dialect::GeminiLive);
    assert!(pair.iter().all(|u| u.dialect.is_duplex_upstream()));
}

/// Every unit of a session leaves a record, including the one that opened it, and the operation
/// class it leaves under is the one the plane declared. "A session opened" is not an event kind
/// of its own: the record's shape is fixed for every plane and a plane contributes two ids.
#[test]
fn the_opening_unit_seals_under_the_declared_operation_class() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let before = node
        .durability
        .lock()
        .expect("record chain")
        .record
        .sealed();
    let _ = run(&kernel, &unit);
    let after = node
        .durability
        .lock()
        .expect("record chain")
        .record
        .sealed();
    assert_eq!(after, before + 1, "exactly one record for one unit");

    // Read back what the record itself would carry, not a separate mapping the audit step never
    // touches: `UnitShape::op_class()` and `meta::OP_SESSION_OPEN` are the same expression on both
    // sides of that comparison, so it cannot see a class written wrong onto the record's own field.
    let inputs = unit.audit_inputs(
        &ctx(1),
        busbar_caps::Outcome::Completed,
        busbar_contract::FinishClass::Complete,
    );
    assert_eq!(
        inputs.what.op_class,
        busbar_unit_audit::record::OpClassId::new("voice.session.open"),
        "the record's own op_class field must carry the plane's literal class name"
    );
}

/// A lease that answers "nothing left" closes the session it answered for.
///
/// The turn that emptied it is served and settled in full — audio that has already streamed
/// cannot be refunded, so refusing it would be a refusal of value the caller already received.
/// The frame AFTER it is the enforcement point, and it is refused at the door under the money
/// reason, which is the same one the kernel reads to close a session rather than merely to end
/// a unit. A session that never ran dry is untouched by any of this.
#[test]
fn a_session_whose_lease_runs_dry_is_closed_and_its_next_frame_refused() {
    struct DryLease;
    impl SessionLease for DryLease {
        fn reserve(&self, _session: u64, _nanos: u64) -> Result<(), ReasonCode> {
            Ok(())
        }
        fn settle(&self, _session: u64, _nanos: u64) -> bool {
            false
        }
        fn close(&self, _session: u64) {}
    }
    let node = priced_node(VoiceIo {
        dial: Box::new(OpenDial),
        lease: Box::new(DryLease),
        ..VoiceIo::default()
    });
    let kernel = Kernel::new();

    // The turn that empties the lease runs to the end and settles.
    let turn = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_tokens_out: 120,
            audio_ms_in: 900,
            ..TurnUsage::default()
        });
    let Ended::Settled { end, .. } = run(&kernel, &turn) else {
        panic!("the exit path settles it");
    };
    assert_eq!(end.outcome(), Outcome::Completed);
    assert_eq!(
        end.into_posted().expect("the report fits").settled(),
        121,
        "the frame that emptied the lease is charged exactly what it delivered: the 120 emitted \
         audio tokens plus the one second of audio it took in"
    );

    // And the next frame on that session does not get in.
    let next =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    let Ended::Settled { end, .. } = run(&kernel, &next) else {
        panic!("the exit path settles it");
    };
    assert_eq!(
        end.outcome(),
        Outcome::Refused(busbar_caps::StepName::Admit, ReasonCode::OverBudget),
        "the door refuses a session that cannot pay for another frame"
    );
    assert_eq!(
        busbar_kernel::inflight::hard_closes(
            busbar_caps::OriginKind::Provider,
            busbar_caps::StepName::Admit,
            ReasonCode::OverBudget,
            busbar_contract::Framing::Stream,
            busbar_kernel::inflight::Binding::Bound,
        ),
        Some(busbar_kernel::inflight::HardClose::ProviderRefusedForMoney),
        "and that refusal is the one that closes the session"
    );

    // A session that never ran dry is not caught by the mark.
    let other =
        VoiceUnit::new(&node, UnitShape::Turn, 8, 1_700_000_000).charging_through(ungoverned());
    let Ended::Settled { end, .. } = run(&kernel, &other) else {
        panic!("the exit path settles it");
    };
    assert_eq!(end.outcome(), Outcome::Completed);

    // And a NEW session on the same identifier is a new session: it takes its own reservation
    // and is not refused for what the last one spent.
    let reopened = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let Ended::Settled { end, .. } = run(&kernel, &reopened) else {
        panic!("the exit path settles it");
    };
    assert_eq!(end.outcome(), Outcome::Completed);
    let turn =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    let Ended::Settled { end, .. } = run(&kernel, &turn) else {
        panic!("the exit path settles it");
    };
    assert_eq!(end.outcome(), Outcome::Completed);
}

/// A refused unit's record says it was refused, and names the step that refused it.
///
/// The record is the only place a refusal survives the connection it happened on, so a chain
/// that spells every ending "completed" is a chain an operator cannot ask why anything stopped.
#[test]
fn a_refused_units_record_carries_the_refusal_and_its_step() {
    let node = node(serviceable());
    let unit =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    let refused = Outcome::Refused(busbar_caps::StepName::Approve, ReasonCode::ScopeDenied);
    let inputs = unit.audit_inputs(&ctx(1), refused, busbar_contract::FinishClass::Error);
    assert_eq!(inputs.outcome.unit_end, refused);
    assert_eq!(inputs.outcome.step, Some(busbar_caps::StepName::Approve));

    // And a turn that ran is still recorded as one: threading the ending through did not turn
    // every record into a refusal.
    let done = unit.audit_inputs(
        &ctx(1),
        Outcome::Completed,
        busbar_contract::FinishClass::TurnComplete,
    );
    assert_eq!(done.outcome.unit_end, Outcome::Completed);
    assert_eq!(done.outcome.step, None);
}

/// The four seams refuse rather than pretend. A node whose I/O half was never installed cannot
/// dial, cannot pump, cannot lease and has no carrier; saying so at the seam is what keeps
/// "detached" from being reported as "broken", and keeps neither from being reported as "fine".
#[test]
fn the_detached_seams_refuse_honestly() {
    let io = VoiceIo::default();
    assert_eq!(
        io.dial.dial(&DialTarget {
            pool: "voice".into(),
            lane: 0,
            url: "wss://example.invalid".into(),
            policy: GuardPolicy::default(),
        }),
        Err(DialRefusal::Detached)
    );
    assert!(!io.pump.is_pumping(7));
    assert!(io.lease.reserve(7, 1).is_err());
    assert!(!io.lease.settle(7, 1));
    assert!(!io.carrier.available());
}

/// The kernel-granted scope a handshake runs under is the transport's, never a policy key. A
/// deployment cannot revoke it by leaving it out of a table, which is what makes shaking hands
/// possible before anybody is authenticated.
#[test]
fn the_handshake_scope_is_the_kernel_granted_one() {
    assert_eq!(handshake_scope(), "transport:handshake");
}

// -----------------------------------------------------------------------------------------
// The tool calls a session waits on
// -----------------------------------------------------------------------------------------

/// The correlation a client's reply carries, as the plane reads it off the bytes.
fn reply(call_id: &str) -> CorrelationRef<'_> {
    CorrelationRef {
        fact_key: busbar_plane_voice::plane::FACT_TOOL_CORRELATION,
        value: CorrelationValue::Str(call_id),
    }
}

/// Run one tool-call unit far enough to plan its leg, which is where the wait is entered.
fn plan(kernel: &Kernel, node: &VoiceNode, key: u64, call_id: &str, now_ms: Millis) -> Ended {
    plan_on(kernel, node, 7, key, call_id, now_ms)
}

/// [`plan`], on a named session — the shape a cell needs when the session identifier is not this
/// module's to choose because the served door minted it.
fn plan_on(
    kernel: &Kernel,
    node: &VoiceNode,
    session: u64,
    key: u64,
    call_id: &str,
    now_ms: Millis,
) -> Ended {
    let unit = VoiceUnit::new(node, UnitShape::ToolCall, session, 1_700_000_000)
        .charging_through(ungoverned())
        .calling(call_id)
        .at_ms(now_ms);
    let cell = busbar_caps::HoldCell::new(busbar_caps::Hold::open(
        &kernel.admit_token(),
        PrincipalId::new("acct:voice"),
        0,
    ));
    let gauge = ConcurrencyGauge::new();
    let canary = Canary::new();
    let leases = busbar_kernel::slice::LeaseCell::new();
    let meter = AccrualMeter::new();
    run_unit(
        kernel,
        &unit,
        &ctx(key),
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

/// **Two calls open at once, and each reply wakes only its own.**
///
/// A turn that asks for two tools opens two units. They are identical apart from the identifier
/// each minted — same key, same selector, same deadline — which is exactly the pair that a wait
/// on a constant, or on a fold of an identifier, is free to confuse. The replies come back in
/// the opposite order to the calls, so "whichever is waiting" cannot pass either.
#[test]
fn two_tool_calls_on_one_session_each_wake_only_the_call_they_answer() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let (weather, tide) = (11, 22);
    let _ = plan(&kernel, &node, weather, "call_aaa", 0);
    let _ = plan(&kernel, &node, tide, "call_bbb", 0);
    assert_eq!(node.tool_calls.open(), 2, "two calls are open, not one");

    // The SECOND call answers first.
    assert_eq!(
        node.tool_calls.replied(7, reply("call_bbb")),
        Ok(UnitKey::new(tide)),
        "the reply wakes the call whose identifier it carries"
    );
    assert!(
        node.tool_calls.waiting(7, UnitKey::new(weather)),
        "and leaves the other call waiting on its own identifier, untouched"
    );
    assert_eq!(
        node.tool_calls.replied(7, reply("call_aaa")),
        Ok(UnitKey::new(weather)),
        "which is still there for its own answer"
    );
    assert_eq!(node.tool_calls.open(), 0, "and both calls are settled");
    assert_eq!(
        node.tool_calls.ending(7, UnitKey::new(weather)),
        Some(CallEnd::Answered),
        "each unit reads its own ending, once"
    );
}

/// A reply nobody is waiting for is refused, not dropped.
///
/// The temptation the refusal exists to remove is "there is one call open, so this must be for
/// it". Paying a hold out against an answer that named something else is the failure a
/// correlation exists to prevent, and it costs a real principal real money.
#[test]
fn a_reply_for_a_call_nobody_opened_is_refused_rather_than_dropped() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let _ = plan(&kernel, &node, 11, "call_aaa", 0);

    assert_eq!(
        node.tool_calls.replied(7, reply("call_zzz")),
        Err(ReplyRefused::UnknownCall),
        "an unmatched reply is not paid out against the only call standing"
    );
    assert_eq!(
        node.tool_calls.replied(9, reply("call_aaa")),
        Err(ReplyRefused::NoSuchSession),
        "and the same identifier on another session is another conversation's business"
    );
    assert!(
        node.tool_calls.waiting(7, UnitKey::new(11)),
        "the open call is untouched by either"
    );
    assert_eq!(
        node.tool_calls.replied(7, reply("call_aaa")),
        Ok(UnitKey::new(11)),
        "and still answers to its own identifier"
    );
}

/// **An unanswered call ends at the deadline it declared.**
///
/// The wait is entered with the plane's own thirty seconds; the sweep at thirty-one names it,
/// and the unit's exit path ends it under the deadline rather than settling as though the answer
/// had arrived. Before this was wired the wait was entered nowhere at all, so an unanswered call
/// was a hold nothing ever closed.
#[test]
fn an_unanswered_tool_call_ends_at_the_deadline_its_leg_declared() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let _ = plan(&kernel, &node, 11, "call_aaa", 0);
    let _ = plan(&kernel, &node, 22, "call_bbb", 20_000);

    let deadline = u64::from(busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000;
    assert!(
        node.tool_calls.expired(deadline - 1).is_empty(),
        "a call is not swept one millisecond before its own deadline"
    );
    assert_eq!(
        node.tool_calls.expired(deadline + 1),
        vec![UnansweredCall {
            session: 7,
            unit: UnitKey::new(11)
        }],
        "the first call's deadline is up; the one opened twenty seconds later is not"
    );
    assert_eq!(
        node.tool_calls.open(),
        1,
        "the second call is still waiting"
    );

    // The exit: the unit is resumed and reads what became of its wait.
    let Ended::Settled { end, .. } = plan(&kernel, &node, 11, "call_aaa", deadline + 1) else {
        panic!("the exit path settles an unanswered call like anything else");
    };
    assert!(
        matches!(
            end.outcome(),
            Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded)
        ),
        "got {:?}",
        end.outcome()
    );
}

/// A call that minted no identifier is not entered as a wildcard.
///
/// A wait with no identity matches the first reply that arrives, whoever it was for. Refusing
/// the unit says so where it happens rather than at the first reply that goes to the wrong call.
#[test]
fn a_tool_call_that_minted_no_identifier_is_refused_rather_than_entered() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let unit =
        VoiceUnit::new(&node, UnitShape::ToolCall, 7, 1_700_000_000).charging_through(ungoverned());
    let Ended::Settled { end, .. } = run(&kernel, &unit) else {
        panic!("the exit settles it");
    };
    assert!(
        matches!(
            end.outcome(),
            Outcome::Refused(_, ReasonCode::NoDestination)
        ),
        "got {:?}",
        end.outcome()
    );
    assert_eq!(node.tool_calls.open(), 0, "and nothing is waiting");
}

/// **The port the served path reaches the table through.**
///
/// Every assertion above drives [`OpenToolCalls`] directly, which is the right way to judge the
/// table but says nothing about whether anything on a socket can get to it. This judges the seam
/// the session runtime holds: the same three answers — woken, refused, swept — asked in the
/// spelling `busbar-voice` asks them in. Before this port existed the runtime had no way to ask.
#[cfg(feature = "plane-voice")]
#[test]
fn the_runtimes_port_reaches_the_nodes_own_table() {
    use busbar_voice::runtime::{GovernedCalls, ReplyRefusal};

    let kernel = Kernel::new();
    let node = std::sync::Arc::new(node(serviceable()));
    let _ = plan(&kernel, &node, 11, "call_aaa", 0);
    let _ = plan(&kernel, &node, 22, "call_bbb", 0);
    let port = NodeCalls::new(std::sync::Arc::clone(&node));

    assert_eq!(
        port.replied(9, "call_aaa"),
        Err(ReplyRefusal::NoSuchSession),
        "a reply on a session this node holds nothing for wakes nothing"
    );
    assert_eq!(
        port.replied(7, "call_zzz"),
        Err(ReplyRefusal::UnknownCall),
        "and one naming a call nobody is waiting on is refused, not matched to whichever is open"
    );
    assert_eq!(
        port.replied(7, "call_bbb"),
        Ok(()),
        "the answer wakes its own"
    );
    assert!(
        !node.tool_calls.waiting(7, UnitKey::new(22)),
        "which is the wait leaving the table"
    );
    assert!(
        node.tool_calls.waiting(7, UnitKey::new(11)),
        "and the call it did not answer is still waiting"
    );

    // The tick's sweep, through the same port, at the deadline the plane's own leg declared.
    let deadline = u64::from(busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000;
    assert_eq!(port.expired(deadline - 1), 0, "not one millisecond early");
    assert_eq!(
        port.expired(deadline + 1),
        1,
        "the unanswered call is swept"
    );

    // And what the sweep left behind is what ends the unit — under its own deadline, not as a
    // settlement that pretends the answer arrived.
    let Ended::Settled { end, .. } = plan(&kernel, &node, 11, "call_aaa", deadline + 1) else {
        panic!("the exit path settles an unanswered call like anything else");
    };
    assert!(
        matches!(
            end.outcome(),
            Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded)
        ),
        "got {:?}",
        end.outcome()
    );
}

/// **THE ROOT IDENTITY: on the served composition there is no ungoverned session left to reach.**
///
/// Two things are judged here and they are the two halves of one claim.
///
/// The first is that the root composes at all. `mount_root_voice` seals the registry and then
/// writes this node's open-call table onto the served door; after it has run, the door's own
/// per-session binding answers with a table rather than with nothing, and it answers with a
/// fresh identifier each time — which is what a session is told apart by on a node where two
/// conversations may carry identical call identifiers. Before this the port and its implementor
/// both existed and no served session had ever been handed one.
///
/// The second is what that binding is worth: a call nobody answers, ended THROUGH the served
/// path. The tick is the session pump's own `sweep_expired`, the table is this node's, and the
/// wall is the plane's declared `TOOL_REPLY_DEADLINE_SECS` read rather than restated — not one
/// millisecond early, and the unit that was waiting exits `Failed(Route, DeadlineExceeded)`
/// rather than settling as though the answer had arrived.
#[cfg(all(feature = "root-voice", feature = "plane-voice"))]
#[test]
fn the_served_composition_has_no_ungoverned_session_left_in_it() {
    use busbar_voice::runtime::{Carrier, MeteringPort, SessionCore};

    // (1) THE ROOT'S OWN COMPOSITION. First writer wins on the plane's side, so this cell is the
    // one place in the crate that writes it, and it writes it the way `main()` does.
    crate::compose_voice_governed_calls();
    let bound = busbar_voice::mount::served_governed_session()
        .expect("after the root has mounted, every session the door opens is bound to a table");
    let next = busbar_voice::mount::served_governed_session()
        .expect("and so is the next one, on its own identifier");
    assert_ne!(
        bound.session, next.session,
        "two conversations are told apart before either has a call open"
    );
    assert_eq!(
        bound.calls.replied(bound.session, "call_aaa"),
        Err(busbar_voice::runtime::ReplyRefusal::NoSuchSession),
        "the table the door was handed is a real one, holding nothing at boot"
    );

    // (2) WHAT THE BINDING IS WORTH, through a real session pump. The node here is the cell's
    // own, reached through the same port the door was handed, because the node `main()` composed
    // is not a handle this cell holds.
    let kernel = Kernel::new();
    let node = std::sync::Arc::new(node(serviceable()));
    let session = 4_242;
    let _ = plan_on(&kernel, &node, session, 11, "call_aaa", 0);
    assert!(
        node.tool_calls.waiting(session, UnitKey::new(11)),
        "the leg was planned, so the wait is entered"
    );

    let lease = busbar_voice::runtime::LocalMeteringPort
        .reserve(1_000, 0, None)
        .expect("an uncapped lease always opens");
    let core = SessionCore::new(
        busbar_voice::ir::codec::OpenAiRealtimeCodec,
        lease,
        None,
        std::sync::Arc::new(busbar_voice::runtime::EchoToolExecutor),
        Carrier::sideband(),
        None,
    )
    .with_governed(busbar_voice::runtime::GovernedSession {
        session,
        calls: std::sync::Arc::new(NodeCalls::new(std::sync::Arc::clone(&node))),
    });
    assert_eq!(
        core.governed_session(),
        Some(session),
        "the pump knows itself by the identifier the door minted"
    );

    let deadline = u64::from(busbar_plane_voice::plane::TOOL_REPLY_DEADLINE_SECS) * 1_000;
    assert_eq!(
        core.sweep_expired(deadline - 1),
        0,
        "the session's own tick ends nothing one millisecond before the declared deadline"
    );
    assert_eq!(
        core.sweep_expired(deadline),
        1,
        "and ends the unanswered call at it"
    );

    let Ended::Settled { end, .. } = plan_on(
        &kernel,
        &node,
        session,
        11,
        "call_aaa",
        Millis::from(deadline as u32),
    ) else {
        panic!("the exit path settles an unanswered call like anything else");
    };
    assert!(
        matches!(
            end.outcome(),
            Outcome::Failed(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded)
        ),
        "got {:?}",
        end.outcome()
    );
}

/// A conversation that is over cannot answer anything.
#[test]
fn a_closed_session_stops_waiting_on_the_calls_it_had_open() {
    let kernel = Kernel::new();
    let node = node(serviceable());
    let _ = plan(&kernel, &node, 11, "call_aaa", 0);
    node.tool_calls.closed(7);
    assert_eq!(node.tool_calls.open(), 0);
    assert_eq!(
        node.tool_calls.replied(7, reply("call_aaa")),
        Err(ReplyRefused::NoSuchSession)
    );
}

// -----------------------------------------------------------------------------------------
// The hold's five acts, on this plane
// -----------------------------------------------------------------------------------------

/// A node whose card prices the dialect, so a turn's estimate is a figure rather than a zero.
fn priced_node(io: VoiceIo) -> VoiceNode {
    let mut node = node(io);
    let mut rates = std::collections::BTreeMap::new();
    rates.insert(
        Dialect::OpenaiRealtime.name().to_string(),
        busbar_unit_admission::RateNanos::from_micros_per_token(2.0, 5.0, 0.0, 0.0),
    );
    node.pricer = Pricer::with_card(0, rates);
    node
}

/// A handshake reserves nothing of its own, and takes the SESSION's opening reservation on the
/// lease. The two are different things and the distinction is the whole design: no money moves
/// in unit zero, but the conversation it opens is allowed against a figure taken here, because a
/// live session cannot be metered after the fact.
#[test]
fn unit_zero_reserves_nothing_itself_and_takes_the_sessions_opening_reservation() {
    /// A lease that records what it was reserved for.
    struct Recording(std::sync::Mutex<Vec<u64>>);
    impl SessionLease for Recording {
        fn reserve(&self, _session: u64, nanos: u64) -> Result<(), ReasonCode> {
            self.0.lock().expect("lock").push(nanos);
            Ok(())
        }
        fn settle(&self, _session: u64, _nanos: u64) -> bool {
            true
        }
        fn close(&self, _session: u64) {}
    }
    let seen = std::sync::Arc::new(Recording(std::sync::Mutex::new(Vec::new())));
    struct Shared(std::sync::Arc<Recording>);
    impl SessionLease for Shared {
        fn reserve(&self, session: u64, nanos: u64) -> Result<(), ReasonCode> {
            self.0.reserve(session, nanos)
        }
        fn settle(&self, session: u64, nanos: u64) -> bool {
            self.0.settle(session, nanos)
        }
        fn close(&self, session: u64) {
            self.0.close(session);
        }
    }
    let node = priced_node(VoiceIo {
        dial: Box::new(OpenDial),
        lease: Box::new(Shared(std::sync::Arc::clone(&seen))),
        ..VoiceIo::default()
    });
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    assert_eq!(
        unit.estimate(),
        Estimate::zero(),
        "no money moves in unit 0"
    );
    let opening = unit.session_opening_nanos();
    assert!(opening > 0, "a priced dialect names a session budget");

    let _ = run(&Kernel::new(), &unit);
    assert_eq!(
        *seen.0.lock().expect("lock"),
        vec![opening],
        "the lease was taken for the session's opening reservation, once"
    );
}

/// The flat fee is the SESSION's, drawn on the unit that opens it, and it is drawn once.
///
/// A turn is a frame of a conversation already paid for, the provider's tool call is not a
/// caller's request, a session whose leg never opened relayed nothing, and an ending the plane
/// called an error pays nothing.
#[test]
fn the_flat_fee_is_the_session_open_and_nothing_else() {
    use busbar_caps::OriginKind;
    use busbar_contract::FinishClass;
    use busbar_kernel::teller::fee_count;

    let open = |finish| {
        fee_evidence(
            UnitShape::SessionOpen,
            OriginKind::Client,
            true,
            true,
            Some(finish),
        )
    };
    assert_eq!(fee_count(&open(FinishClass::Complete)).0, 1);
    assert_eq!(fee_count(&open(FinishClass::Error)).0, 0);
    // A session that named no upstream, and one whose dial never opened: neither reached a leg,
    // and a fee is for a connection that was actually made.
    assert_eq!(
        fee_count(&fee_evidence(
            UnitShape::SessionOpen,
            OriginKind::Client,
            false,
            true,
            Some(FinishClass::Complete),
        ))
        .0,
        0
    );
    assert_eq!(
        fee_count(&fee_evidence(
            UnitShape::SessionOpen,
            OriginKind::Client,
            true,
            false,
            Some(FinishClass::Complete),
        ))
        .0,
        0
    );
    // A turn of a conversation the session already paid to open pays nothing, however it ended.
    for finish in [FinishClass::TurnComplete, FinishClass::Error] {
        assert_eq!(
            fee_count(&fee_evidence(
                UnitShape::Turn,
                OriginKind::Client,
                true,
                true,
                Some(finish),
            ))
            .0,
            0
        );
    }
    // The provider's own push through the session's leg is not a caller's request.
    assert_eq!(
        fee_count(&fee_evidence(
            UnitShape::ToolCall,
            OriginKind::Provider,
            true,
            true,
            Some(FinishClass::TurnComplete),
        ))
        .0,
        0
    );
}

/// **THREE TURNS ON ONE SESSION PAY ONE FLAT FEE.**
///
/// The rule the whole finding turns on, measured over the loop rather than over the evidence
/// function: a conversation is billed one flat fee for the connection that carried it, no matter
/// how many times the caller speaks. Charged per turn, this session paid three — and a real call
/// is not three turns, it is hundreds. The hold agrees: the fee is reserved once, on the
/// session's opening reservation, and no turn's estimate reserves one.
#[test]
fn a_three_turn_session_pays_one_flat_fee() {
    let kernel = Kernel::new();
    let node = priced_node(VoiceIo {
        dial: Box::new(OpenDial),
        lease: Box::new(OpenLease),
        ..VoiceIo::default()
    });

    let opening = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let Ended::Settled {
        fee: opening_fee, ..
    } = run(&kernel, &opening)
    else {
        panic!("the exit path settles the open");
    };
    assert_eq!(opening_fee, 1, "the session's one flat fee, at the open");

    let mut turn_fees = 0;
    for _ in 0..3 {
        let turn = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
            .charging_through(ungoverned())
            .reporting(TurnUsage {
                audio_tokens_out: 30,
                audio_ms_in: 400,
                ..TurnUsage::default()
            });
        let Ended::Settled { fee, end, .. } = run(&kernel, &turn) else {
            panic!("the exit path settles a turn");
        };
        assert_eq!(end.outcome(), Outcome::Completed, "the turn was served");
        turn_fees += fee;
    }
    assert_eq!(
        opening_fee + turn_fees,
        1,
        "one session, one flat fee, however many turns rode it"
    );

    // And the reservation side says the same. The turn's estimate reserves no fee; the session's
    // opening figure carries the one there is.
    let turn = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000);
    assert_eq!(turn.estimate().fee_nanos, 0, "no turn reserves a fee");
    let mut fee_bearing = priced_node(serviceable());
    fee_bearing.pricer = Pricer::flat(25);
    let open = VoiceUnit::new(&fee_bearing, UnitShape::SessionOpen, 7, 1_700_000_000);
    assert_eq!(
        open.session_fee_nanos(),
        25 * NANOS_PER_CENT,
        "the card's per-request fee, in nano-units"
    );
    assert!(
        open.session_opening_nanos() >= open.session_fee_nanos(),
        "and the session's opening reservation is what carries it"
    );
}

/// A TURN THAT SPOKE ONLY IN TEXT BILLS ITS TEXT.
///
/// The exit's located figure is the whole report and not one class of it. A turn that emitted no
/// audio at all is an ordinary shape of turn on this plane — a transcript-only exchange, a
/// tool-driven turn, a dialect answering in text — and reading only the emitted-audio class made
/// every one of them settle a completed turn at nothing while the session's lease had already
/// been drawn down by the same report in full. The lease and the posting read ONE number here.
#[test]
fn a_text_only_turn_settles_the_text_it_metered() {
    use busbar_kernel::teller::settle_amount;

    let node = priced_node(serviceable());
    let usage = TurnUsage {
        text_tokens_in: 40,
        text_tokens_out: 60,
        ..TurnUsage::default()
    };
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(usage);
    let evidence = unit.evidence(&ctx(1));
    assert_eq!(
        evidence.located,
        Some(100),
        "the located figure is every class the turn metered"
    );
    assert_eq!(
        settle_amount(&Outcome::Completed, &evidence).0,
        usage.total(),
        "a completed turn posts what it metered, not what it drew the lease at"
    );
}

/// A PAID TURN'S RECORD NAMES THE PRINCIPAL IT CHARGED, and a refusal before anyone was named
/// still names an arrival.
///
/// The subject is what makes a row belong to an account. Written as `Arrival` on every unit, the
/// chain carried a full set of settled turns that no account could be shown, no revocation could
/// be traced through and no dispute could be answered from. The principal is the auth chain's,
/// recorded at the first step the loop hands it over on, and read back here.
#[test]
fn a_paid_turns_record_names_its_principal() {
    use crate::root::kernel::auth_bindings::AuthBindings;
    use busbar_contract::{KeyFacts, VirtualKeyDirectory};
    use busbar_unit_audit::record::Subject;

    // A door the fixture must actually pass, with a directory that resolves the credential to a
    // KNOWN id — "key-voice-1" — rather than running behind the open door, where every non-empty
    // string (including the anonymous admit) would satisfy a merely-non-empty check. Storing the
    // caller's credential string, the group name or a constant instead of `self.principal` is
    // only caught if the record is checked against the exact id the door issued.
    struct OneKey;
    impl VirtualKeyDirectory for OneKey {
        fn operator_token_hash(&self) -> Option<String> {
            None
        }

        fn verify(
            &self,
            credential: &str,
            _now: u64,
            expected_aud: Option<&str>,
        ) -> Option<KeyFacts> {
            (credential == "tok"
                && expected_aud == Some(<VoicePlane as busbar_contract::plane::PlaneMeta>::KEY))
            .then(|| KeyFacts {
                id: "key-voice-1".to_string(),
                name: "an approved key".to_string(),
                scopes: None,
                enabled: true,
                expires_at: None,
                deleted_at: None,
            })
        }

        fn is_revoked(&self, _credential: &str) -> bool {
            false
        }
    }

    let mut node = node_behind(
        serviceable(),
        busbar_unit_admission::GroupTable::default(),
        Auth::new(AuthChain::new(Vec::new(), true)),
        AuthBindings::new(std::sync::Arc::new(OneKey) as _),
    );
    let mut rates = std::collections::BTreeMap::new();
    rates.insert(
        Dialect::OpenaiRealtime.name().to_string(),
        busbar_unit_admission::RateNanos::from_micros_per_token(2.0, 5.0, 0.0, 0.0),
    );
    node.pricer = Pricer::with_card(0, rates);

    let kernel = Kernel::new();
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .with_credential("tok")
        .reporting(TurnUsage {
            audio_tokens_out: 12,
            ..TurnUsage::default()
        });
    let Ended::Settled { end, .. } = run(&kernel, &unit) else {
        panic!("the accepted credential runs the turn to its end");
    };
    assert!(
        matches!(end.outcome(), Outcome::Completed),
        "the control credential must be accepted, got {:?}",
        end.outcome()
    );
    let inputs = unit.audit_inputs(
        &ctx(1),
        Outcome::Completed,
        busbar_contract::FinishClass::TurnComplete,
    );
    assert_eq!(
        inputs.subject,
        Subject::PrincipalId("key-voice-1".to_string()),
        "the record must name the credential's own resolved principal, not merely some non-empty \
         string"
    );

    // And the unit that never reached verify — a refusal before any principal existed — is an
    // arrival, which is the one thing `Arrival` is the honest answer to.
    let unseen = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000);
    let refused = unseen.audit_inputs(
        &ctx(1),
        Outcome::Refused(busbar_caps::StepName::Decode, ReasonCode::DecodeFailed),
        busbar_contract::FinishClass::Error,
    );
    assert!(matches!(refused.subject, Subject::Arrival));
}

/// THE KERNEL'S OWN FLOOR IS THE AUDIO THAT CAME IN, IN THE UNIT ITS CLASS IS DENOMINATED IN.
///
/// The floor is what the one settlement row that reads it posts, so its unit and its label are
/// money. It counts uplink milliseconds and the class the plane declares for uplink audio is in
/// seconds: reported verbatim it is a thousand times the duration, and reported under the
/// emitted-audio token class it is a duration priced at a token rate, in the wrong direction.
#[test]
fn the_floor_is_inbound_audio_in_the_declared_classs_own_unit() {
    use busbar_kernel::teller::settle_amount;

    let node = priced_node(serviceable());
    let kernel = Kernel::new();
    // Two and a half seconds of uplink audio, and no report from the upstream at all: the shape
    // that reaches the floor row.
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_ms_in: 2_500,
            ..TurnUsage::default()
        });
    let _ = run(&kernel, &unit);
    let evidence = unit.evidence(&ctx(1));
    assert_eq!(
        evidence.accrued_floor, 3,
        "2_500 ms is three seconds of billable audio, not 2_500 of anything"
    );
    let class = evidence.class.expect("the plane still declares the class");
    assert_ne!(
        class,
        meta::CLASS_AUDIO_TOKENS_OUT,
        "what the kernel counted is not the audio the turn emitted"
    );
    assert!(
        <VoicePlane as busbar_contract::plane::PlaneMeta>::METER_CLASSES
            .iter()
            .any(|decl| decl.key == class
                && decl.direction == busbar_contract::ids::ClassDirection::Input),
        "and the class it is counted under is one the plane declares, on the inbound side"
    );
    // The floor row: a live end that is not a completion with nothing located posts the floor.
    let end = Outcome::Refused(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded);
    let floor_only = Evidence {
        located: None,
        ..evidence
    };
    assert_eq!(settle_amount(&end, &floor_only).0, 3);
}

/// A STREAM THAT ENDED ON AN ERROR BILLS NOTHING, even with a figure located.
///
/// The settlement table has a row for exactly this — a live end that is not a completion, with
/// something located, whose stream carried an error signal — and it posts zero. Reaching that
/// row takes the plane saying the stream errored, and this file used to say the opposite
/// unconditionally: every dropped session, every upstream failure, every refused frame settled
/// in full for audio the caller never got the end of. The ending is the one the audit step
/// already sealed, so the record and the posting cannot tell two stories about one turn.
#[test]
fn an_errored_turn_bills_nothing_though_it_located_a_figure() {
    use busbar_kernel::teller::settle_amount;

    let node = priced_node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_tokens_out: 120,
            ..TurnUsage::default()
        });
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let token: UnitToken<Audit> = UnitToken::mint(&seal);
    let refusal = Refusal::new(ReasonCode::DeadlineExceeded);
    let _ = unit.audit_refused(&token, &ctx(1), &refusal);

    let evidence = unit.evidence(&ctx(1));
    assert!(
        evidence.terminal_error,
        "the plane sealed an error ending and the evidence says so"
    );
    assert_eq!(evidence.located, Some(120), "the figure is still located");
    let end = Outcome::Refused(busbar_caps::StepName::Route, ReasonCode::DeadlineExceeded);
    assert_eq!(
        settle_amount(&end, &evidence).0,
        0,
        "and an errored stream posts nothing against it"
    );

    // And the completing turn beside it is untouched: the derivation only ever reads what the
    // plane sealed, so a turn that finished cleanly still settles what it metered.
    let clean = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_tokens_out: 120,
            ..TurnUsage::default()
        });
    let _ = clean.audit(&token, &ctx(1), &Outcome::Completed);
    assert!(!clean.evidence(&ctx(1)).terminal_error);
}

/// A turn that reported no output relayed no answer; one that emitted tokens did.
#[test]
fn an_answered_turn_is_one_that_emitted_something() {
    let node = priced_node(serviceable());
    let silent = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_tokens_in: 90,
            ..TurnUsage::default()
        });
    assert!(!silent.answered());
    let spoken = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_tokens_out: 3,
            ..TurnUsage::default()
        });
    assert!(spoken.answered());
}

/// A turn's reservation is the coarse opening magnitude at the dearest price the dialect's
/// classes charge, and the door is what opens it. Over-sized on purpose: the residual comes
/// straight back at settlement.
#[test]
fn a_turn_opens_a_reservation_the_door_sized_off_the_estimate() {
    let node = priced_node(serviceable());
    let unit =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    // 5 micro-units per output token is 5_000 nano-units, and it is the dearest of the four.
    let estimate = unit.estimate();
    assert_eq!(estimate.per_class.len(), 1);
    assert_eq!(estimate.per_class[0].max_unit_price_nanos, 5_000);
    assert_eq!(
        estimate.hold_nanos(busbar_unit_admission::STANDARD_TIER_BP),
        TURN_OPENING_TOKENS * 5_000
    );

    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let admit = busbar_caps::AdmitToken::<Admit>::mint(&seal);
    let token: UnitToken<Admit> = UnitToken::mint(&seal);
    let admission = unit
        .admit(
            &token,
            &admit,
            &ctx(1),
            &PrincipalId::new("acct:voice"),
            &[],
            &GroupLeaseSlip::new(),
        )
        .into_result(&seal)
        .expect("the empty chain admits");
    match admission {
        busbar_caps::Admission::Own(hold) => {
            assert_eq!(hold.reserved(), TURN_OPENING_TOKENS * 5_000);
            assert_eq!(hold.accrued(), 0, "a reservation is not a spend");
            let _ = busbar_caps::Posted::settle(
                hold,
                0,
                &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(&seal), Vec::new())
                    .expect("empty"),
                &busbar_caps::LedgerToken::mint(&seal),
            );
        }
        other => panic!("a priced turn opens a hold of its own, got {other:?}"),
    }
}

/// THE DOOR'S COUNT LEAVES THE DOOR'S STEP, or this plane's `concurrent` caps are decoration.
///
/// A yes raises a gauge per capped group in the chain and the value it hands back is what holds
/// them up. Dropped where the decision was taken, the gauges are back to where they started
/// before the admitted unit has run a single step, and the next arrival is judged against a
/// count of nothing however many units are in flight. So the step has to hand the count over,
/// and the slip is where. The kernel does the rest: it belongs to the unit's slot from here,
/// and it goes back at whichever of the unit's two ends arrives first.
///
/// The chain this deployment hands the door declares no capped group, so the count here is of
/// none — which is exactly why the assertion is about the HANDOVER and not about a number. A
/// step that keeps the grant caps nothing on any chain; a step that hands it over caps every
/// group the chain names.
#[test]
fn the_door_step_hands_its_count_to_the_slot_rather_than_dropping_it() {
    let node = priced_node(serviceable());
    let unit =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let admit = busbar_caps::AdmitToken::<Admit>::mint(&seal);
    let token: UnitToken<Admit> = UnitToken::mint(&seal);
    let leases = GroupLeaseSlip::new();

    let admission = unit
        .admit(
            &token,
            &admit,
            &ctx(1),
            &PrincipalId::new("acct:voice"),
            &[],
            &leases,
        )
        .into_result(&seal)
        .expect("the chain admits");
    assert!(
        leases.grant_taken().is_some(),
        "the door's own count came out of the step, where the loop can put it on the slot"
    );
    if let busbar_caps::Admission::Own(hold) = admission {
        let _ = busbar_caps::Posted::settle(
            hold,
            0,
            &busbar_caps::Usage::report(&busbar_caps::UsageToken::mint(&seal), Vec::new())
                .expect("empty"),
            &busbar_caps::LedgerToken::mint(&seal),
        );
    }
}

/// A refusal hands over nothing, because a refusal counted nothing.
///
/// The other half of the rule, and the one that keeps the handover from becoming a leak: the
/// grant only exists on a yes, so a slip that carried one out of a refusal would be a count on
/// a group for a unit that never ran. The handshake is this plane's admission that never
/// reaches the chain at all.
#[test]
fn an_admission_that_never_reaches_the_chain_hands_over_no_count() {
    let node = priced_node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let admit = busbar_caps::AdmitToken::<Admit>::mint(&seal);
    let token: UnitToken<Admit> = UnitToken::mint(&seal);
    let leases = GroupLeaseSlip::new();

    let _ = unit
        .admit(
            &token,
            &admit,
            &ctx(1),
            &PrincipalId::new("acct:voice"),
            &[],
            &leases,
        )
        .into_result(&seal)
        .expect("a handshake is admitted holding nothing");
    assert!(
        leases.grant_taken().is_none(),
        "the handshake never asked the door, so there is no count to hold"
    );
}

/// **The lifecycle, end to end.** The door opens the reservation, the meter accrues against it,
/// the exit path settles it, and the posting moves this plane's balance and lands on the
/// journal. Before the exit arm was bound, the last two of those four happened nowhere.
#[test]
fn a_turn_opens_accrues_settles_and_lands_on_the_journal() {
    let node = priced_node(serviceable());
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_tokens_out: 120,
            audio_ms_in: 900,
            ..TurnUsage::default()
        });
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let kernel = Kernel::new();
    let Ended::Settled { end, .. } = run(&kernel, &unit) else {
        panic!("the exit path settles it");
    };
    let posted = end.into_posted().expect("the usage report fits the record");
    assert_eq!(
        posted.reserved(),
        TURN_OPENING_TOKENS * 5_000,
        "what the door reserved"
    );
    // What the settlement table posts is the WHOLE report — every class the turn metered, which
    // here is 120 emitted audio tokens and the one second of audio the turn took in — not what
    // the kernel's meter counted; the accrual is the floor beside it, and the hold carries both.
    assert_eq!(posted.settled(), 121, "what the turn metered");
    assert_eq!(posted.overdraft(), 0, "well inside the reservation");
    assert_eq!(
        posted.released(),
        TURN_OPENING_TOKENS * 5_000 - 121,
        "and the residual the settlement hands back"
    );

    let who = PrincipalId::new("acct:voice");
    let settled = unit
        .settle(&who, posted, &busbar_caps::DurabilityToken::mint(&seal))
        .expect("the memory-buffered journal takes it");
    assert_eq!(
        settled.settlement.released,
        i128::from(TURN_OPENING_TOKENS * 5_000 - 121)
    );
    assert!(settled.overdraft.is_none());

    let durability = node.durability.lock().expect("lock");
    let key = VoiceUnit::balance(&who);
    let window = busbar_unit_admission::budget_window(
        busbar_unit_admission::window::WINDOW_DAY,
        1_700_000_000,
    );
    assert_eq!(durability.ledger.book().get(&key, window).settled, 121);
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(
        replayed.len(),
        1,
        "one posting, one record — and no overdraft record beside it"
    );
}

/// A turn that outruns the coarse estimate tops the reservation up out of the headroom its own
/// leg offered while it ran, rather than carrying the excess. The overdraft is the last resort,
/// not the ordinary answer to a guess that was low.
#[test]
fn a_turn_past_its_estimate_grows_the_reservation_out_of_the_offered_headroom() {
    let node = priced_node(serviceable());
    let reserved = TURN_OPENING_TOKENS * 5_000;
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000)
        .charging_through(ungoverned())
        .reporting(TurnUsage {
            audio_tokens_out: 3,
            // Far past what the door sized for, and the chain this node runs caps nothing.
            audio_ms_in: reserved + 12_345,
            ..TurnUsage::default()
        });
    assert_eq!(
        unit.headroom_nanos(),
        u64::MAX,
        "an unconfigured chain caps no spend, so there is no ceiling to grow into"
    );
    let Ended::Settled { end, .. } = run(&Kernel::new(), &unit) else {
        panic!("the exit path settles it");
    };
    let posted = end.into_posted().expect("the report fits the record");
    assert_eq!(
        posted.reserved(),
        reserved + 12_345,
        "the reservation grew to cover the spend"
    );
    assert_eq!(posted.overdraft(), 0, "so nothing had to be carried");
    assert!(!posted
        .flags()
        .contains(busbar_caps::PostingFlags::OVERDRAFT));
}

/// The other end of the same lifecycle: a turn that ran far past what the door sized for it.
/// It is not refused, it is not trimmed, and what nothing backed becomes a record of its own.
#[test]
fn a_turn_that_outruns_its_reservation_posts_in_full_and_carries_the_rest() {
    let node = priced_node(serviceable());
    let who = PrincipalId::new("acct:voice");
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();

    // The hold the door would have opened, and a spend far past it with an empty slice behind.
    let reserved = TURN_OPENING_TOKENS * 5_000;
    let mut hold = busbar_caps::Hold::open(
        &busbar_caps::AdmitToken::<Admit>::mint(&seal),
        who.clone(),
        reserved,
    );
    let spend = hold.spend(reserved + 7_000, 0);
    assert_eq!(
        spend.accrued,
        reserved + 7_000,
        "the spend is never trimmed"
    );
    assert_eq!(spend.overdraft, 7_000);

    let usage = busbar_caps::Usage::report(
        &busbar_caps::UsageToken::mint(&seal),
        vec![UsageLine {
            class: MeterClassId::new("audio_tokens_out"),
            quantity: reserved + 7_000,
            source: QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line");
    let posted = busbar_caps::Posted::settle(
        hold,
        u128::from(reserved + 7_000),
        &usage,
        &busbar_caps::LedgerToken::mint(&seal),
    );
    assert!(posted
        .flags()
        .contains(busbar_caps::PostingFlags::OVERDRAFT));

    let unit =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    let settled = unit
        .settle(&who, posted, &busbar_caps::DurabilityToken::mint(&seal))
        .expect("the journal takes both records");
    let note = settled
        .settlement
        .overdraft
        .as_ref()
        .expect("the ledger noted the carry");
    assert_eq!(note.principal, "acct:voice");
    assert_eq!(note.amount, 7_000);

    let durability = node.durability.lock().expect("lock");
    let window = busbar_unit_admission::budget_window(
        busbar_unit_admission::window::WINDOW_DAY,
        1_700_000_000,
    );
    let figures = durability
        .ledger
        .book()
        .get(&VoiceUnit::balance(&who), window);
    assert_eq!(figures.settled, i128::from(reserved + 7_000));
    assert_eq!(figures.overdraft_carried_out, 7_000);
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert_eq!(replayed.len(), 2, "the posting, then the carry");
}

// ── the decode step's own scaffolding ──────────────────────────────────────────────────────
//
// The production half of this file names no wire shape and no dialect, and it stays that way.
// But the decode step's whole content is the plane's reading of a frame, so a cell that drove
// it from a shape this module chose would be asserting its own answer. These build the four
// borrowed views and the one resource a plugin call is given, so the plane's own decoder can be
// handed a real frame.

/// A leaking arena. Test-only, run a bounded number of times per process: the trait's
/// allocators hand back borrowed slices, so an honest double either leaks or is unsafe.
struct CellArena;

impl busbar_contract::bounded::Arena for CellArena {
    fn alloc_bytes<'a>(
        &'a self,
        src: &[u8],
    ) -> Result<busbar_contract::bounded::ArenaBytes<'a>, busbar_contract::bounded::ArenaBudget>
    {
        let leaked: &'static [u8] = Box::leak(src.to_vec().into_boxed_slice());
        Ok(busbar_contract::bounded::ArenaBytes::new(leaked))
    }

    fn alloc_str<'a>(
        &'a self,
        src: &str,
    ) -> Result<&'a str, busbar_contract::bounded::ArenaBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, busbar_contract::bounded::Span)],
    ) -> Result<
        &'a [(&'a str, busbar_contract::bounded::Span)],
        busbar_contract::bounded::ArenaBudget,
    > {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

struct CellConfig;

impl busbar_contract::unit::ConfigView for CellConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

/// The socket surface, composed the way a voice session arrives on it.
struct CellTransport;

impl busbar_contract::unit::TransportView for CellTransport {
    fn key(&self) -> &'static str {
        "ws"
    }
    fn chain(&self) -> &[&'static str] {
        &["tcp", "tls", "http", "ws"]
    }
    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

/// One inbound frame carrying `body`.
fn one_frame(body: &str) -> Vec<busbar_contract::wire::Frame> {
    vec![busbar_contract::wire::Frame {
        direction: busbar_contract::wire::Direction::Inbound,
        stream: busbar_contract::ids::StreamId(0),
        bytes: busbar_contract::bounded::SlabBytes::new(std::sync::Arc::from(body.as_bytes())),
        meta: busbar_contract::wire::FrameMeta::default(),
    }]
}

/// A client event on an open session resolves to a turn or to a frame of the turn already open,
/// and a carrier frame this session's dialect cannot read resolves to neither.
///
/// The decode step of this plane carries a shape the pump already read, so the question the step
/// answers is not "what are these bytes" — it is whether the class the loop goes on to price and
/// audit under is the class the plane's own reader produced. Three answers are driven.
///
/// A first client event OPENS a turn: any client event does, not audio specifically, because a
/// session's first frame is routinely `session.update` and there is no reason to hold a session
/// without a unit to carry its facts and size its hold. A second event on the same session does
/// NOT open a second one — it relays onto the turn's own correlation, which is what "one open
/// unit per direction" means, and a tool result is exactly that kind of frame. And a frame the
/// session's dialect cannot read is refused at the step that read it, rather than opening a unit
/// under a class nobody decoded.
#[test]
fn a_client_event_opens_a_turn_and_a_later_one_relays_onto_it() {
    use busbar_caps::KernelSeal;
    use busbar_contract::bounded::Labels;
    use busbar_contract::plane::{Ingress, Plane, PlaneSessionState};
    use busbar_contract::unit::{Clock, Ctx};
    use busbar_contract::wire::FrameCursor;
    use busbar_plane_voice::session::VoiceSessionState;

    let seal = KernelSeal::acquire_for_kernel();
    let arena = CellArena;
    let config = CellConfig;
    let transport = CellTransport;
    let labels = Labels::new();
    let clock = Clock {
        unix_secs: 1_700_000_000,
        monotonic_nanos: 0,
    };
    let plane = VoicePlane::new(UPSTREAMS);
    let mut state = PlaneSessionState::new(VoiceSessionState::for_dialect(Dialect::OpenaiRealtime));

    // The first client event of the session. `session.update` is what a real client sends
    // first, and it opens the turn.
    let frames = one_frame(r#"{"type":"session.update","session":{}}"#);
    let mut cursor = FrameCursor::new(&frames);
    let pctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &pctx)
        .expect("a client event this dialect names is readable");
    let Ingress::Open(draft) = ingress else {
        panic!("the first client event opens a turn, got {ingress:?}");
    };
    let opened = draft.op;
    let correlation = draft
        .correlation_out
        .expect("an opened turn mints the correlation its frames relay under");

    // The class the plane produced is the class the step carries. Not "a" turn class — THE one,
    // read off the plane's answer rather than restated, so a shape that drifted from the plane's
    // own vocabulary goes red here instead of pricing under a name nothing declares.
    let node = node(serviceable());
    let unit =
        VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(ungoverned());
    assert_eq!(
        unit.decode(&UnitToken::mint(&seal), &ctx(1))
            .into_result(&seal)
            .expect("a turn proceeds"),
        opened
    );
    // And it is a class this plane DECLARES. A step carrying a class outside the declared set
    // would be a unit the audit record and the rate card have no row for.
    for shape in [UnitShape::SessionOpen, UnitShape::Turn, UnitShape::ToolCall] {
        assert!(
            <VoicePlane as busbar_contract::plane::PlaneMeta>::OP_CLASSES
                .contains(&shape.op_class()),
            "{shape:?} carries a class this plane never declared"
        );
    }

    // A tool result on the same session. It is a client event that relays rather than opening
    // a second unit, and it names the CALL it answers, not the turn it rode in on: two calls
    // open on one session at one moment are told apart by that identifier alone.
    let frames = one_frame(
        r#"{"type":"conversation.item.create","item":{"type":"function_call_output","call_id":"c-1","output":"42"}}"#,
    );
    let mut cursor = FrameCursor::new(&frames);
    let pctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
    let ingress = plane
        .decode_ingress(&mut cursor, Some(&mut state), &pctx)
        .expect("a tool result is a client event this dialect names");
    let Ingress::Frame { for_, .. } = ingress else {
        panic!("a later client event relays, got {ingress:?}");
    };
    assert_eq!(
        for_,
        Some(CorrelationRef {
            fact_key: busbar_plane_voice::plane::FACT_TOOL_CORRELATION,
            value: CorrelationValue::Str("c-1"),
        })
    );
    let _ = correlation;

    // A session bound to the telephony carrier, handed bytes that are not that carrier's shape.
    // The refusal is raised at the step that read them, and no unit exists to have been given a
    // class.
    let mut telephony =
        PlaneSessionState::new(VoiceSessionState::for_dialect(Dialect::TwilioMediaStreams));
    let frames = one_frame("not a carrier frame at all");
    let mut cursor = FrameCursor::new(&frames);
    let pctx = Ctx::new(clock, &config, None, &transport, &labels, &arena);
    assert_eq!(
        plane.decode_ingress(&mut cursor, Some(&mut telephony), &pctx),
        Err(busbar_contract::wire::Decode::Malformed)
    );
}
/// A credential is resolved through the node's own signed-key seam, and the audience is this
/// plane's own name.
///
/// Three answers on one session, because the third is the one an open front door hides. A good
/// credential resolves to the key's identity. A credential the directory does not hold resolves
/// to nothing and the unit is refused before it can reach a destination. And a credential that
/// IS valid — genuinely minted, genuinely unexpired — but was minted for another plane's
/// audience is refused HERE, at this plane's ingress, rather than at the upstream it was going
/// to reach: an audience that is declared and never checked is not an audience.
#[test]
fn a_credential_is_resolved_against_this_planes_own_audience() {
    use crate::root::kernel::auth_bindings::AuthBindings;
    use busbar_caps::{Authenticated, KernelSeal};
    use busbar_contract::{KeyFacts, VirtualKeyDirectory};

    /// One key, minted for one audience.
    struct Directory;

    impl VirtualKeyDirectory for Directory {
        fn operator_token_hash(&self) -> Option<String> {
            None
        }

        fn verify(
            &self,
            credential: &str,
            _now: u64,
            expected_aud: Option<&str>,
        ) -> Option<KeyFacts> {
            // The audience is the plane boundary and the verifier is where it is enforced. Both
            // credentials below are real keys; only one of them was minted for this plane.
            let minted_for = match credential {
                "voice-tok" => "voice",
                "mcp-tok" => "mcp",
                _ => return None,
            };
            (expected_aud == Some(minted_for)).then(|| KeyFacts {
                id: "key-voice-1".to_string(),
                name: "an approved key".to_string(),
                scopes: None,
                enabled: true,
                expires_at: None,
                deleted_at: None,
            })
        }

        fn is_revoked(&self, _credential: &str) -> bool {
            false
        }
    }

    // A closed chain naming the signed-key arm and no boxed module, so the arm is the only
    // thing that can open the door and this cell is about that arm.
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    let node = VoiceNode::new(VoiceNodeParts {
        plane: VoicePlane::new(UPSTREAMS),
        groups: crate::root::policy::group_table(
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
        ),
        pricer: Pricer::flat(0),
        auth: Auth::new(AuthChain::new(Vec::new(), true)),
        auth_bindings: AuthBindings::new(std::sync::Arc::new(Directory)),
        scope: scope_policy(),
        meter_policy: crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        durability,
        io: serviceable(),
        origin: Kernel::new().origin(busbar_caps::OriginKind::Client),
    });

    let seal = KernelSeal::acquire_for_kernel();
    let answer = |credential: Option<&str>| {
        let mut unit = VoiceUnit::new(&node, UnitShape::SessionOpen, 7, 1_700_000_000);
        if let Some(credential) = credential {
            unit = unit.with_credential(credential);
        }
        unit.authenticate(&UnitToken::mint(&seal), &ctx(1))
            .into_result(&seal)
    };

    // Minted for this plane: admitted, carrying the key's own id, which is what the audit row
    // and the settlement are attributed to.
    match answer(Some("voice-tok")) {
        Ok(Authenticated::Principal(who)) => assert_eq!(who.as_str(), "key-voice-1"),
        other => panic!("a key minted for this plane opens the session: {other:?}"),
    }

    // A credential the directory does not hold, and no credential at all. The chain is closed,
    // so neither is the anonymous principal — both are refusals, and both are raised before the
    // unit reaches a destination.
    for absent in [Some("forged"), None] {
        let refusal = answer(absent)
            .err()
            .unwrap_or_else(|| panic!("{absent:?} must not open a session"));
        assert_eq!(refusal.reason(), ReasonCode::Unauthenticated);
        assert_eq!(refusal.step(), Some(busbar_caps::StepName::Authenticate));
    }

    // The one that matters: a real key, for the wrong plane. Refused here rather than carried
    // to an upstream that would have honoured it.
    let refusal =
        answer(Some("mcp-tok")).expect_err("another plane's audience does not open this one");
    assert_eq!(refusal.reason(), ReasonCode::Unauthenticated);
}

// ─────────────────────────────────────────────────────────────────────
// The configured group reaches the door
// ─────────────────────────────────────────────────────────────────────

/// One group, one turn at a time — the smallest cap an operator can write.
fn one_turn_at_a_time(group: &str) -> busbar_unit_admission::GroupTable {
    let groups = std::collections::BTreeMap::from([(
        group.to_string(),
        busbar_substrate::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_substrate::config::groups::LimitCfg {
                metric: busbar_substrate::config::groups::LimitMetric::Concurrent,
                amount: 1,
                per: None,
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            child_default: None,
        },
    )]);
    // Through the interner the root uses at boot, so the name the slot records is the same
    // static the vocabulary holds rather than one this fixture invented.
    let mut vocabulary = crate::root::vocabulary::Vocabulary::new();
    let ids = vocabulary.group_ids(&crate::root::vocabulary::ConfigKeys {
        groups: vec![group.to_string()],
        ..crate::root::vocabulary::ConfigKeys::default()
    });
    crate::root::policy::group_table(&groups, &ids)
}

/// Ask the door for one turn, keeping what its yes counted.
fn ask_the_door(
    kernel: &Kernel,
    unit: &VoiceUnit<'_>,
    who: &PrincipalId,
) -> (Result<Admission, busbar_caps::Refusal>, GroupLeaseSlip) {
    let slip = GroupLeaseSlip::new();
    let decision = Units::admit(
        unit,
        &busbar_caps::UnitToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel()),
        &kernel.admit_token(),
        &ctx(1),
        who,
        &[],
        &slip,
    );
    (
        decision.into_result(&busbar_caps::KernelSeal::acquire_for_kernel()),
        slip,
    )
}

/// **The cap is a cap.** A deployment that wrote `concurrent: 1` against a voice group gets one
/// turn in the air at a time: the second is refused while the first is still running, and it is
/// admitted once the first has ended.
///
/// This is the whole point of the chain being the configured one. With an empty chain the door
/// walks no group, raises no gauge and says yes to both — which is what a node whose operator
/// wrote this cap down did, silently, with nothing on any surface to say the limit was inert.
#[test]
fn a_voice_group_capped_at_one_turn_refuses_the_second_and_admits_it_after_the_first_ends() {
    const GROUP: &str = "voice-team";
    let node = node_governed_by(serviceable(), one_turn_at_a_time(GROUP));
    let kernel = Kernel::new();
    let who = PrincipalId::new("acct:voice");
    // Resolved once, at the open. Every turn below is lent this one value.
    let chain = node.chain_for(&who, Some(GROUP)).expect("configured");
    let turn = || VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);

    let first = turn();
    let (admitted, held) = ask_the_door(&kernel, &first, &who);
    assert!(admitted.is_ok(), "the first turn of a group capped at one");
    assert_eq!(
        held.taken().len(),
        1,
        "and the yes names the one capped group it counted"
    );
    // The count itself, taken onto the slot as the loop takes it. Held for as long as the unit
    // it admitted is running, which is what makes the next line a refusal rather than a second
    // yes.
    let running = held.grant_taken().expect("the yes is holding a count");

    let second = turn();
    let (refused, _) = ask_the_door(&kernel, &second, &who);
    let refusal = refused.expect_err("the group is full");
    assert_eq!(
        refusal.reason(),
        ReasonCode::RateLimited,
        "an in-flight gauge is a count cap, not a spend cap"
    );

    // The unit ends: the slot gives back what it held, and the group has room again.
    drop(running);
    let third = turn();
    let (after, _) = ask_the_door(&kernel, &third, &who);
    assert!(
        after.is_ok(),
        "the cap is instantaneous — it gates what is running, never what has run"
    );
}

/// A caller bound to a group this node's configuration does not have is refused, not admitted
/// under caps that could not be read. Fail-closed, and rendered as over-quota, which is what the
/// door itself answers for the same cause.
#[test]
fn a_voice_caller_bound_to_an_unconfigured_group_is_refused() {
    let node = node_governed_by(serviceable(), one_turn_at_a_time("voice-team"));
    let kernel = Kernel::new();
    let who = PrincipalId::new("acct:voice");
    assert!(
        node.chain_for(&who, Some("a-group-this-node-never-had"))
            .is_none(),
        "the group is not in the table, so the session has no chain to lend"
    );
    // And a turn lent none refuses, rather than running under caps nothing could read.
    let unit = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000);
    let (decision, _) = ask_the_door(&kernel, &unit, &who);
    assert_eq!(
        decision
            .expect_err("nothing is admitted under caps that cannot be read")
            .reason(),
        ReasonCode::OverBudget
    );
}

/// The handshake stays exempt. A group capped out still opens its sessions, because unit zero
/// takes no lease of either kind — the posture that keeps an operator's own surface answering
/// while everything else is at its cap.
#[test]
fn a_capped_group_still_opens_a_session() {
    const GROUP: &str = "voice-team";
    let node = node_governed_by(serviceable(), one_turn_at_a_time(GROUP));
    let kernel = Kernel::new();
    let who = PrincipalId::new("acct:voice");
    let chain = node.chain_for(&who, Some(GROUP)).expect("configured");
    let turn = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);
    let (_, held) = ask_the_door(&kernel, &turn, &who);
    let _running = held.grant_taken().expect("the turn is counted");

    let open =
        VoiceUnit::new(&node, UnitShape::SessionOpen, 8, 1_700_000_000).charging_through(&chain);
    let (decision, _) = ask_the_door(&kernel, &open, &who);
    assert!(
        decision.is_ok(),
        "unit zero's admission is the zero-priced one and draws no lease"
    );
}

/// **The chain is lent, never rebuilt.** A live session's turns are frames of a conversation and
/// the door is on every one of them; a chain is a vector of owned bucket ids, so resolving one
/// per turn would put that vector on the admitting path per frame for an answer settled at the
/// open and unable to change under the session.
///
/// So the unit holds a BORROW of what the session resolved. Two turns are handed the same
/// address — the property a per-turn `chain_for` cannot have however cheap it looks. The pin is
/// on the reference rather than on an allocation count because this crate has no library target
/// for a counting-allocator test binary to reach.
#[test]
fn two_turns_of_one_session_are_handed_the_same_chain() {
    const GROUP: &str = "voice-team";
    let node = node_governed_by(serviceable(), one_turn_at_a_time(GROUP));
    let who = PrincipalId::new("acct:voice");
    let chain = node.chain_for(&who, Some(GROUP)).expect("configured");

    let first = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);
    let second = VoiceUnit::new(&node, UnitShape::Turn, 7, 1_700_000_000).charging_through(&chain);
    let (Some(one), Some(two)) = (first.chain, second.chain) else {
        panic!("both turns were lent the session's chain");
    };
    assert!(
        std::ptr::eq(one, two),
        "one resolved chain, lent twice — not two copies of one answer"
    );
    assert!(
        std::ptr::eq(one, &chain),
        "and it is the session's own value"
    );
}

// ------------------------------------------------------------------------------------------------
// THE STATUS LEG THIS PLANE DECLARES, AND THE KERNEL ARM IT REACHES
// ------------------------------------------------------------------------------------------------

/// **THE PLANE SAYS WHERE ITS STATUS IS, AND THIS LEG READS IT.**
#[test]
fn the_leg_carries_the_status_leg_the_plane_declares() {
    let declared =
        <busbar_plane_voice::VoicePlane as busbar_contract::plane::PlaneMeta>::STATUS_LEG;
    assert!(
        declared.is_some(),
        "this dialect answers on a frame, so it has a status leg to declare"
    );
    let evidence = fee_evidence(
        UnitShape::SessionOpen,
        busbar_caps::OriginKind::Client,
        true,
        true,
        Some(busbar_contract::FinishClass::TurnComplete),
    );
    assert_eq!(
        evidence.status_at, declared,
        "the leg builds the kernel's evidence from what the plane declares"
    );
}

/// **A SESSION THAT DIES AFTER IT WAS OPENED REACHES THE KERNEL'S DISPUTE ARM.**
///
/// The caller connected, the one leg was dialled, and the frame that opens the conversation went
/// back — the unit that PAYS is that open, and it was answered. The session then dies. Calling the
/// whole thing an error and posting nothing would refund a connection the node really made; posting
/// silently would hide that the two readings disagree. The kernel does neither, in one place, for
/// every plane.
#[test]
fn a_session_that_dies_after_it_opened_is_disputed() {
    let evidence = fee_evidence(
        UnitShape::SessionOpen,
        busbar_caps::OriginKind::Client,
        true,
        true,
        Some(busbar_contract::FinishClass::Error),
    );
    let (fee, flags) = busbar_kernel::teller::fee_count(&evidence);
    assert_eq!(
        fee, 1,
        "the frame the caller saw decides the fee, on this plane and on every other"
    );
    assert!(
        flags.contains(busbar_caps::PostingFlags::METER_DISPUTED),
        "the frame the caller saw and the plane's finish contradict each other"
    );
}
