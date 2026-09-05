// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seams where two units name the same object at two widths, and the boot check on two label
//! banks kept in step by hand.
//!
//! ## Why these exist at all, and why none of them is a defect
//!
//! A unit names no other unit. That is what makes each one testable on its own and what stops a
//! change in one from reaching through into another. The price is that when two units genuinely do
//! talk about the same thing — a pool member, a failure disposition — neither can name the other's
//! type, and something has to hold the mapping. That something is the composition root, and this
//! file is where it holds it.
//!
//! So an adapter here is not a workaround for a mistake in either crate. It is the seam the shape
//! predicted, and each one has a reference in the tree that proved the two real APIs meet.
//!
//! The breaker adapter below is the production binding of the seam that
//! `busbar-unit-egress/tests/breaker_adapter.rs` proved was implementable. That file stays where it
//! is: it lives under the egress unit's own tests so it can never be reached from that crate's
//! source, and it is what keeps the egress unit's port honest if this file ever stops existing. The
//! difference between the two is the one that matters — the reference closes over a default
//! configuration, and this one refuses to.
//!
//! ## The three
//!
//! 1. **Breaker to egress.** The egress unit's port takes no configuration and the breaker unit's
//!    method requires it, because the cooldown ladder is a per-pool declaration and the walk has no
//!    business knowing about ladders. The adapter closes over the configuration. **The one thing it
//!    must not do is close over a default**, which is the hazard the whole adapter exists around:
//!    a default ladder silently applies the wrong cooldowns, a lane recovers early or stays down,
//!    and nothing about the code looks wrong. So the configuration is per-pool, supplied, and
//!    missing-means-refuse rather than missing-means-default.
//!
//! 2. **Trust to breaker.** The trust unit's pre-walk filter keys on a lane's index in the pool's
//!    own table; the breaker and egress units key on a destination. Both name the pool member, from
//!    two sides, and the root holds the one mapping. This is not a width that could have been
//!    unified away: the trust unit's filter runs BEFORE a candidate set exists, so at that point
//!    there is nothing to have a destination identity yet.
//!
//! 3. **The label banks.** Two crates carry the same four metric label strings as separate
//!    literals, deliberately, because they share no dependency to point at one constant. They reach
//!    the scrape as label VALUES, so a drift between them is a wire change nobody would see in a
//!    diff. The check below compares them at boot. It does not introduce a shared constant: the two
//!    crates have no common dependency that could hold one, and putting an open-vocabulary key
//!    where the kernel could compare against it is the thing the lean-core scan exists to catch.

use busbar_caps::{Route, UnitToken};
use busbar_contract::StatusClass;
use busbar_unit_breaker::cfg::BreakerCfg;
use busbar_unit_breaker::classify::Diagnostics;
use busbar_unit_breaker::journal::NoopJournal;
use busbar_unit_breaker::{Breaker as BreakerUnitTrait, BreakerUnit, DestinationId};
use busbar_unit_egress::ports::{
    Admit, Breaker, Classified, Disposition, Outcome, Unavailable, UpstreamStatus,
};
use std::collections::HashMap;
use std::sync::Arc;

/// The per-pool breaker configuration the adapter closes over.
///
/// A pool with no entry is a refusal to guess, not a fall back to the defaults. The whole hazard
/// this adapter is written around is a stale or default ladder applying the wrong cooldowns
/// invisibly, so an unconfigured pool is something a reader can see went wrong rather than
/// something that quietly behaves like a configured one.
#[derive(Debug, Default, Clone)]
pub struct BreakerPolicy {
    per_pool: HashMap<String, BreakerCfg>,
    fallback: Option<BreakerCfg>,
}

impl BreakerPolicy {
    /// A policy with no pool configured and no fallback.
    #[must_use]
    pub fn new() -> Self {
        BreakerPolicy::default()
    }

    /// Declare one pool's ladder.
    #[must_use]
    pub fn with_pool(mut self, pool: impl Into<String>, cfg: BreakerCfg) -> Self {
        self.per_pool.insert(pool.into(), cfg);
        self
    }

    /// Declare the ladder for the default cell — direct and ad-hoc routes, which run under the
    /// empty pool name and are not a configured pool at all.
    #[must_use]
    pub fn with_default_cell(mut self, cfg: BreakerCfg) -> Self {
        self.fallback = Some(cfg);
        self
    }

    /// The ladder in force for one pool, if the configuration declared one.
    #[must_use]
    pub fn for_pool(&self, pool: &str) -> Option<&BreakerCfg> {
        self.per_pool.get(pool).or(self.fallback.as_ref())
    }
}

/// The breaker unit's `error_map` diagnostic sink, as the root holds one.
///
/// A shared trait object rather than a concrete type, so the sink a deployment binds and the sink a
/// test asserts against are the same shape and the breaker unit's type parameter does not become a
/// parameter of everything that holds a [`BreakerAdapter`]. The breaker crate already implements
/// its own trait for `Arc<S>`, which is what makes the handle usable on both sides at once.
pub type DiagnosticsSink = Arc<dyn Diagnostics + Send + Sync>;

/// The breaker unit as this root composes it: no journal, and a real diagnostics sink.
pub type RootBreakerUnit = BreakerUnit<NoopJournal, DiagnosticsSink>;

/// The breaker unit's one diagnostic, delivered through the node's own logging.
///
/// The breaker crate takes no logging dependency, so the warning an unrecognized `error_map` class
/// deserves has to be raised by something that does. This is that something, and it is deliberately
/// nothing more: it formats no policy, decides no disposition, and cannot change what the mapping
/// classified as — the mapping is ignored either way, exactly as the previous release ignored it.
/// What it adds is the line saying so.
///
/// The line is a `WARN` carrying the catalog's `diag` field, which is the same tracing path every
/// other operator-facing configuration warning takes, so an operator greps for the code and lands on
/// the entry that explains it. It fires on the first upstream error that reaches an unrecognized
/// mapping and never at boot — which is why a configuration the previous release booted silently
/// still boots with exactly the lines it booted with then.
///
/// Warned ONCE per distinct value: the dedup is the breaker crate's own `WarnOnceDiagnostics`, which
/// [`root_diagnostics`] wraps this in, rather than a second copy of the same set here.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingDiagnostics;

impl Diagnostics for TracingDiagnostics {
    fn unrecognized_error_map_value(&self, value: &str) {
        tracing::warn!(
            diag = %busbar_substrate::diagnostics::CONFIG_ERROR_MAP_CLASS_UNRECOGNIZED.banner(),
            error_map_value = value,
            "error_map maps an error to an unrecognized status class; the mapping is IGNORED and \
             classification falls through to HTTP status. Valid classes: rate_limit, overloaded, \
             server_error, timeout, network, auth, billing, client_error, context_length"
        );
    }
}

/// The sink the root binds the breaker unit to: the node's logging, warned once per distinct value.
#[must_use]
pub fn root_diagnostics() -> DiagnosticsSink {
    Arc::new(busbar_unit_breaker::classify::WarnOnceDiagnostics::new(
        TracingDiagnostics,
    ))
}

/// The egress unit's breaker port, bound to the breaker unit.
///
/// A thin wrapper with no policy of its own beyond the two folds the module doc names. What it must
/// never do is decide anything: a disposition is the breaker unit's data and a route is the egress
/// unit's walk, and an adapter that split the difference would be a third opinion nobody asked for.
pub struct BreakerAdapter {
    unit: RootBreakerUnit,
    policy: BreakerPolicy,
}

impl BreakerAdapter {
    /// Bind the egress port to a breaker unit, under a declared per-pool policy.
    #[must_use]
    pub fn new(unit: RootBreakerUnit, policy: BreakerPolicy) -> Self {
        BreakerAdapter { unit, policy }
    }

    /// Bind the egress port to a breaker unit built over one diagnostics sink, under a declared
    /// per-pool policy. The one-call form of [`BreakerAdapter::new`] for a caller that has a sink
    /// rather than a unit — which is every caller in this root, because the unit has no other
    /// configuration to make here.
    #[must_use]
    pub fn with_diagnostics(diagnostics: DiagnosticsSink, policy: BreakerPolicy) -> Self {
        BreakerAdapter::new(BreakerUnit::with_diagnostics(diagnostics), policy)
    }

    /// The breaker unit behind the port, for the boot-time hydration the root does before serving.
    #[must_use]
    pub fn unit(&self) -> &RootBreakerUnit {
        &self.unit
    }

    /// Fold the transport's coarse reading of a frame down to a representative numeric status, for
    /// when no number was reported.
    ///
    /// Success and the catch-all fold to nothing: there is no non-arbitrary number for either, and
    /// the breaker's own "no code" answer — record nothing, relay as-is — is exactly what the
    /// previous release did with an unexpected success reaching the error path.
    fn fold_class(class: Option<StatusClass>) -> Option<u16> {
        match class {
            Some(StatusClass::ClientError) => Some(400),
            Some(StatusClass::ServerError) => Some(500),
            Some(StatusClass::Success | StatusClass::Other) | None => None,
        }
    }
}

fn to_breaker_outcome(outcome: Outcome) -> busbar_unit_breaker::Outcome {
    use busbar_unit_breaker::Outcome as B;
    match outcome {
        Outcome::Success => B::Success,
        Outcome::Transient { retry_after } => B::Transient { retry_after },
        Outcome::HardDown => B::HardDown,
        Outcome::RecordNothing => B::RecordNothing,
    }
}

fn from_breaker_outcome(outcome: busbar_unit_breaker::Outcome) -> Outcome {
    use busbar_unit_breaker::Outcome as B;
    match outcome {
        B::Success => Outcome::Success,
        B::Transient { retry_after } => Outcome::Transient { retry_after },
        B::HardDown => Outcome::HardDown,
        B::RecordNothing => Outcome::RecordNothing,
    }
}

fn from_breaker_disposition(
    disposition: busbar_unit_breaker::classify::Disposition,
) -> Disposition {
    use busbar_unit_breaker::classify::Disposition as B;
    match disposition {
        B::ClientFault => Disposition::ClientFault,
        B::TransientUpstream => Disposition::TransientUpstream,
        B::HardDown => Disposition::HardDown,
        B::ContextLength => Disposition::ContextLength,
    }
}

impl Breaker for BreakerAdapter {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        match self.unit.try_admit(pool, destination, now) {
            Ok(admit) => Ok(Admit {
                probe_epoch: admit.probe_epoch,
            }),
            Err(state) => Err(match state {
                busbar_unit_breaker::LaneState::Suppressed { until } => {
                    Unavailable::BreakerOpen { until }
                }
                busbar_unit_breaker::LaneState::ProbeInFlight => Unavailable::ProbeInFlight,
                busbar_unit_breaker::LaneState::BudgetExhausted => Unavailable::BudgetExhausted,
                // The unit errs only on a non-ready state, so this arm is unreachable by
                // construction rather than by convention.
                busbar_unit_breaker::LaneState::Ready => {
                    unreachable!("the breaker unit does not refuse a ready cell")
                }
            }),
        }
    }

    fn ready(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &UnitToken<Route>,
    ) -> bool {
        matches!(
            self.unit.state(pool, destination, now, token),
            busbar_unit_breaker::LaneState::Ready
        )
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        // The destination-scoped fact the breaker unit holds is the lifetime budget. Whether a
        // destination is administratively down is declared configuration, which is the egress and
        // configuration layer's to know and not this unit's. Answered from `budget_remaining`
        // alone, never from the sealed `state`/`observe`, so no token crosses here.
        self.unit.budget_remaining(destination) != Some(0)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &UnitToken<Route>,
    ) -> u64 {
        match self.unit.state(pool, destination, now, token) {
            busbar_unit_breaker::LaneState::Suppressed { until } => until.saturating_sub(now),
            _ => 0,
        }
    }

    fn classify(&self, destination: DestinationId, status: UpstreamStatus) -> Classified {
        let code = status.code.or_else(|| Self::fold_class(status.class));
        let classified = self.unit.classify(
            destination,
            busbar_unit_breaker::port::UpstreamStatus {
                code,
                retry_after: status.retry_after,
            },
        );
        Classified {
            disposition: from_breaker_disposition(classified.disposition),
            outcome: from_breaker_outcome(classified.outcome),
            label: classified.label,
        }
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &UnitToken<Route>,
    ) -> bool {
        // THE point of this adapter. The port carries no configuration, the unit requires it, and
        // the ladder is what decides how long a tripped lane stays down. A pool nobody configured
        // gets nothing recorded rather than a default ladder applied in its name: a wrong cooldown
        // is invisible, and a lane that never trips at least shows up as a lane that never trips.
        let Some(cfg) = self.policy.for_pool(pool) else {
            return false;
        };
        self.unit.observe(
            pool,
            destination,
            to_breaker_outcome(outcome),
            cfg,
            now,
            token,
        )
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64) {
        self.unit.release_probe(pool, destination, epoch, now);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.unit.spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.unit.refund_budget(destination);
    }
}

/// The one mapping between a pool member's two names.
///
/// The trust unit's pre-walk filter knows a lane by its index in the pool's own table; the breaker
/// and egress units know a pool member as a destination. The root holds the correspondence because
/// it is the only thing that sees both tables, and it is a `Vec` in table order because that is
/// what the index means.
#[derive(Debug, Default, Clone)]
pub struct LaneMap {
    destinations: Vec<DestinationId>,
}

impl LaneMap {
    /// A map over one pool's members, in the pool's own declaration order.
    #[must_use]
    pub fn new(destinations: Vec<DestinationId>) -> Self {
        LaneMap { destinations }
    }

    /// The destination a lane index names, if the index is in the table.
    ///
    /// An index off the end answers nothing rather than saturating to the last member: a lane the
    /// table does not have is a mistake somewhere upstream, and answering with somebody else's
    /// destination would send a request to the wrong upstream and look like it worked.
    #[must_use]
    pub fn destination(&self, lane: usize) -> Option<DestinationId> {
        self.destinations.get(lane).copied()
    }

    /// The lane index a destination sits at, if it is in this pool.
    #[must_use]
    pub fn lane(&self, destination: DestinationId) -> Option<usize> {
        self.destinations.iter().position(|d| *d == destination)
    }

    /// How many members the pool has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.destinations.len()
    }

    /// Whether the pool has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.destinations.is_empty()
    }
}

/// A label that appears in one crate's bank and not the other's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelDrift {
    /// What the breaker unit calls it.
    pub breaker: &'static str,
    /// What the egress unit calls it.
    pub egress: &'static str,
}

impl std::fmt::Display for LabelDrift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "metric label banks drifted: the breaker unit says `{}` where the egress unit says `{}`",
            self.breaker, self.egress
        )
    }
}

impl std::error::Error for LabelDrift {}

/// Check at boot that the two crates' metric label banks still agree.
///
/// The three labels both crates carry are duplicate literals, kept in step by hand and deliberately
/// not shared: the crates have no common dependency that could hold a constant, and a shared one
/// would put an open-vocabulary key somewhere the lean-core scan forbids. What that leaves is a
/// drift nobody would notice — the labels reach the scrape as label VALUES, so a change on one side
/// is a wire change that looks like an ordinary edit in a diff. Comparing them once, at boot, is
/// what turns the hand-kept convention into something mechanical.
///
/// Two labels are not compared and cannot be: the breaker unit's client-fault label has no egress
/// counterpart (the walk short-circuits before it would use one) and the egress unit's
/// attempt-timeout label has no breaker counterpart (a deadline this side of the wire is not a
/// classification of anything upstream). Both are single-sided by design, not by omission.
///
/// # Errors
///
/// A label present in both banks has different text on the two sides.
pub fn check_label_banks() -> Result<(), LabelDrift> {
    use busbar_unit_breaker::port::label;
    use busbar_unit_egress::ports::disposition;

    for (breaker, egress) in [
        (label::TRANSIENT_UPSTREAM, disposition::TRANSIENT),
        (label::HARD_DOWN, disposition::HARD_DOWN),
        (label::CONTEXT_LENGTH, disposition::CONTEXT_LENGTH),
    ] {
        if breaker != egress {
            return Err(LabelDrift { breaker, egress });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_caps::KernelSeal;

    /// A fresh `UnitToken<Route>` for one `observe`/`ready`/`cooldown_remaining` call — test-only,
    /// minted through the kernel seal exactly as CG-29 says a real deployment would
    /// (`KernelSeal::acquire_for_kernel` is `// contract:` kernel-only outside test modules; the
    /// production adapter above never mints one of its own — it forwards the borrow its caller
    /// lent it).
    fn route_token() -> UnitToken<Route> {
        UnitToken::mint(&KernelSeal::acquire_for_kernel())
    }

    /// A sink for a test that is about a ladder rather than about a diagnostic. The breaker crate's
    /// own noop, at the shared handle's width, so the unit under test is the production one.
    fn silent_sink() -> DiagnosticsSink {
        Arc::new(busbar_unit_breaker::classify::NoopDiagnostics)
    }

    /// A sink that keeps what it was told, so a test can ask whether the value reached it.
    #[derive(Debug, Default)]
    struct RecordingSink(std::sync::Mutex<Vec<String>>);

    impl RecordingSink {
        fn values(&self) -> Vec<String> {
            self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }
    }

    impl Diagnostics for RecordingSink {
        fn unrecognized_error_map_value(&self, value: &str) {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(value.to_string());
        }
    }

    /// The binding, end to end at the adapter's own width: a destination whose operator `error_map`
    /// names a class busbar has no such thing as, one upstream error that hits it, and the value on
    /// the sink the adapter's unit was built over. Without the binding this is the silently-ignored
    /// mapping the previous release had; with it the value is reportable.
    ///
    /// The classification itself is unchanged either way — the mapping is ignored and the error is
    /// classified from its HTTP status — which is the half that keeps the legacy path byte-identical.
    #[test]
    fn an_unrecognized_error_map_class_reaches_the_bound_sink() {
        let sink = Arc::new(RecordingSink::default());
        let breaker = BreakerAdapter::with_diagnostics(
            Arc::clone(&sink) as DiagnosticsSink,
            BreakerPolicy::new().with_pool("pool", a_slow_ladder()),
        );
        let dest = DestinationId::new(9);
        breaker.unit().set_error_map(
            dest,
            HashMap::from([("503".to_string(), "rate_limt".to_string())]),
        );

        let classified = breaker.classify(
            dest,
            UpstreamStatus {
                code: Some(503),
                class: None,
                retry_after: None,
            },
        );

        assert_eq!(
            sink.values(),
            vec!["rate_limt".to_string()],
            "the operator's typo reached the sink the root bound"
        );
        assert_eq!(
            classified.disposition,
            Disposition::TransientUpstream,
            "the mapping is still ignored: a 503 classifies from its HTTP status"
        );
    }

    /// A ladder that is visibly not the default on both axes a cooldown is decided by: it trips on
    /// the first failure rather than on an error rate, and it holds the lane down for five minutes
    /// rather than fifteen seconds.
    fn a_slow_ladder() -> BreakerCfg {
        BreakerCfg {
            base_cooldown_secs: 300,
            max_cooldown_secs: 600,
            trip: busbar_unit_breaker::cfg::TripConfig {
                mode: busbar_unit_breaker::cfg::TripMode::Consecutive,
                consecutive_n: 1,
                ..busbar_unit_breaker::cfg::TripConfig::default()
            },
            ..BreakerCfg::default()
        }
    }

    fn adapter_for(pool: &str) -> BreakerAdapter {
        BreakerAdapter::with_diagnostics(
            silent_sink(),
            BreakerPolicy::new().with_pool(pool, a_slow_ladder()),
        )
    }

    /// The seam is implementable over the two real APIs, and a fresh destination behaves as both
    /// sides' documentation promises.
    #[test]
    fn a_fresh_destination_is_ready_and_admits() {
        let breaker = adapter_for("pool");
        let dest = DestinationId::new(3);
        assert!(breaker.ready("pool", dest, 0, &route_token()));
        assert!(breaker.admissible(dest));
        assert_eq!(
            breaker.try_admit("pool", dest, 0),
            Ok(Admit { probe_epoch: None })
        );
    }

    /// **The hazard the adapter exists around**, shown as a difference rather than described. One
    /// transient failure, two adapters, two ladders: the configured pool trips on the first failure
    /// and stays down for minutes; the same failure under the crate's default trips nothing at all,
    /// because the default waits for an error rate over a window. An adapter that closed over the
    /// default would produce the second column while the operator read the first, and nothing about
    /// the code would look wrong.
    #[test]
    fn the_configured_ladder_reaches_the_unit_and_not_the_default() {
        let dest = DestinationId::new(1);
        let failure = Outcome::Transient { retry_after: None };

        let configured = adapter_for("pool");
        assert!(
            configured.observe("pool", dest, failure, 0, &route_token()),
            "the configured ladder trips on the first failure"
        );
        let under_configured = configured.cooldown_remaining("pool", dest, 0, &route_token());

        let defaulted = BreakerAdapter::with_diagnostics(
            silent_sink(),
            BreakerPolicy::new().with_pool("pool", BreakerCfg::default()),
        );
        assert!(
            !defaulted.observe("pool", dest, failure, 0, &route_token()),
            "the default ladder waits for an error rate and logs no trip on one failure"
        );
        let under_default = defaulted.cooldown_remaining("pool", dest, 0, &route_token());

        // Both bench the lane, and that is the trap: the difference is not "down" versus "up" but
        // HOW LONG, which nothing on the request path will ever tell anybody about.
        assert!(under_default > 0);
        assert!(
            under_configured > under_default * 4,
            "the cooldown came from the default ladder, not the configured one: \
             {under_configured} against {under_default}"
        );
    }

    /// A pool nobody configured records nothing, rather than having a default ladder applied in its
    /// name. A lane that never trips is visible; a lane that trips for the wrong duration is not.
    #[test]
    fn an_unconfigured_pool_records_nothing_rather_than_guessing() {
        let breaker = BreakerAdapter::with_diagnostics(silent_sink(), BreakerPolicy::new());
        let dest = DestinationId::new(2);

        assert!(!breaker.observe("unknown-pool", dest, Outcome::HardDown, 0, &route_token()));
        assert!(
            breaker.ready("unknown-pool", dest, 0, &route_token()),
            "nothing was recorded, so nothing tripped"
        );
    }

    /// The default cell — direct and ad-hoc routes, running under the empty pool name — is a
    /// declaration of its own rather than a pool that happens to be missing.
    #[test]
    fn the_default_cell_takes_its_own_declared_ladder() {
        let breaker = BreakerAdapter::with_diagnostics(
            silent_sink(),
            BreakerPolicy::new().with_default_cell(a_slow_ladder()),
        );
        let dest = DestinationId::new(4);
        assert!(breaker.observe("", dest, Outcome::HardDown, 0, &route_token()));
        assert!(breaker.cooldown_remaining("", dest, 0, &route_token()) > 0);
    }

    /// The classification comes back through the adapter with the destination's own declared error
    /// map applied — the table is the breaker unit's data and the adapter holds no copy of it.
    #[test]
    fn classification_carries_the_declared_error_map_through() {
        let breaker = adapter_for("pool");
        let dest = DestinationId::new(9);
        breaker.unit().set_error_map(
            dest,
            [("1113".to_string(), "billing".to_string())]
                .into_iter()
                .collect(),
        );

        let out = breaker.classify(
            dest,
            UpstreamStatus {
                class: None,
                code: Some(1113),
                retry_after: None,
            },
        );
        assert_eq!(out.disposition, Disposition::HardDown);
        assert_eq!(out.outcome, Outcome::HardDown);
    }

    /// The one fold the adapter performs: with no numeric status reported, the transport's coarse
    /// reading stands in. This is the shape the walk actually builds today.
    #[test]
    fn a_coarse_transport_reading_stands_in_for_a_missing_status() {
        let breaker = adapter_for("pool");
        let out = breaker.classify(
            DestinationId::new(1),
            UpstreamStatus {
                class: Some(StatusClass::ServerError),
                code: None,
                retry_after: Some(5),
            },
        );
        assert_eq!(out.disposition, Disposition::TransientUpstream);
        assert_eq!(
            out.outcome,
            Outcome::Transient {
                retry_after: Some(5)
            }
        );
    }

    /// A success reaching the error path folds to nothing, which is what the previous release did
    /// with the same case: there is no non-arbitrary number to invent for it.
    #[test]
    fn a_success_folds_to_no_status_at_all() {
        assert_eq!(BreakerAdapter::fold_class(Some(StatusClass::Success)), None);
        assert_eq!(BreakerAdapter::fold_class(Some(StatusClass::Other)), None);
        assert_eq!(BreakerAdapter::fold_class(None), None);
        assert_eq!(
            BreakerAdapter::fold_class(Some(StatusClass::ClientError)),
            Some(400)
        );
        assert_eq!(
            BreakerAdapter::fold_class(Some(StatusClass::ServerError)),
            Some(500)
        );
    }

    /// The lane map is a correspondence, and it round-trips in both directions.
    #[test]
    fn the_lane_map_round_trips_between_the_two_names() {
        let map = LaneMap::new(vec![
            DestinationId::new(11),
            DestinationId::new(22),
            DestinationId::new(33),
        ]);
        assert_eq!(map.len(), 3);
        assert!(!map.is_empty());
        for lane in 0..map.len() {
            let dest = map.destination(lane).expect("in the table");
            assert_eq!(map.lane(dest), Some(lane));
        }
    }

    /// A lane the table does not have answers nothing. Saturating to the last member would send a
    /// request to somebody else's upstream and look like it worked, which is the worst available
    /// failure.
    #[test]
    fn a_lane_off_the_end_of_the_table_names_no_destination() {
        let map = LaneMap::new(vec![DestinationId::new(11)]);
        assert_eq!(map.destination(1), None);
        assert_eq!(map.lane(DestinationId::new(99)), None);
    }

    /// An empty pool has no members and says so, rather than answering for a member it does not
    /// have.
    #[test]
    fn an_empty_pool_names_nothing() {
        let map = LaneMap::default();
        assert!(map.is_empty());
        assert_eq!(map.destination(0), None);
    }

    /// The boot check on the two hand-kept banks. It passes today, which is the point: it is a
    /// tripwire on a convention, not a repair of a break.
    #[test]
    fn the_two_label_banks_agree() {
        assert!(check_label_banks().is_ok());
    }

    /// And the values themselves, written out, so a change on either side has to change this file
    /// too. A label that reaches the scrape is wire, and wire that only one test knows about is
    /// wire nobody is holding.
    #[test]
    fn the_shared_labels_are_the_expected_wire_values() {
        use busbar_unit_breaker::port::label;
        use busbar_unit_egress::ports::disposition;

        assert_eq!(label::TRANSIENT_UPSTREAM, "transient_upstream");
        assert_eq!(label::HARD_DOWN, "hard_down");
        assert_eq!(label::CONTEXT_LENGTH, "context_length");
        assert_eq!(disposition::TRANSIENT, "transient_upstream");
        assert_eq!(disposition::HARD_DOWN, "hard_down");
        assert_eq!(disposition::CONTEXT_LENGTH, "context_length");
        // The two single-sided labels, pinned so that a later attempt to pair them has to notice
        // they were never a pair.
        assert_eq!(label::CLIENT_FAULT, "client_fault");
        assert_eq!(disposition::ATTEMPT_TIMEOUT, "attempt_timeout");
    }

    /// The drift the check would catch, shown as a value rather than left to the imagination.
    #[test]
    fn a_drifted_bank_reads_as_a_drift() {
        let drift = LabelDrift {
            breaker: "transient_upstream",
            egress: "transient-upstream",
        };
        assert!(drift.to_string().contains("drifted"));
    }
}
