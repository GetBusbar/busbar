//! The telemetry face: what a caller stamps when it closes a request out, and the one bound it
//! runs first.
//!
//! Seven methods, no state, no return value but the label bound. Every argument is a `&str` or a
//! number the CALLER names — the face carries no vocabulary of its own, so a body that grows a
//! ninth protocol or a fourth governance surface adds nothing here. That is the whole reason it is
//! a face and not a match: the caller names itself, and the host records what it was told.
//!
//! `pool_label` is on this trait rather than beside it because it is not a separate favour: it is
//! the CARDINALITY BOUND every emit path below has to run before it can hand a client-supplied
//! name to a metric label, and separating the two is how an unbounded label series gets opened.

/// Stamp the request-completion metrics, count the dispatch/failover/translation events, and bound
/// a client-supplied name to a label that cannot open an unbounded series.
///
/// The implementor owns the recorder; the caller owns the words. Nothing here is fallible and
/// nothing here returns a decision — telemetry that can refuse a request is not telemetry.
pub trait Telemetry: Send + Sync {
    /// Stamp the labelled request-completion metric family for one finished request.
    ///
    /// The caller hands its own `(surface, ingress_protocol, pool, outcome, seconds)` and the
    /// implementor records the completion, so the caller never names the host's own snapshot to
    /// close a request out. `surface` is the caller's name for itself, taken as DATA: the face
    /// neither enumerates the surfaces nor branches on one.
    fn request_finished(
        &self,
        surface: &str,
        ingress_protocol: &str,
        pool: &str,
        outcome: &'static str,
        seconds: f64,
    );

    /// Count ONE dispatch ATTEMPT on `(pool_label, lane)`.
    ///
    /// `pool_label` is the BOUNDED metric label — a configured pool name, or the routed name for
    /// the default cell — and is expected to have come from [`pool_label`](Self::pool_label).
    /// `lane` is the index the implementor resolves the `lane` label from off its own snapshot.
    fn telemetry_upstream_attempt(&self, pool_label: &str, lane: usize);

    /// Count ONE classified upstream FAILURE on `(pool_label, lane)` by `disposition`.
    ///
    /// The twin of [`telemetry_upstream_attempt`](Self::telemetry_upstream_attempt);
    /// `disposition` is `'static` because the classification vocabulary is fixed at compile time
    /// and a runtime string there would be an unbounded label.
    fn telemetry_upstream_failure(&self, pool_label: &str, lane: usize, disposition: &'static str);

    /// Count ONE logical closed-to-open breaker TRIP on `(pool_label, lane)`.
    fn telemetry_breaker_trip(&self, pool_label: &str, lane: usize);

    /// Count ONE FAILOVER event on `pool_label` by `reason`, `'static` for the same bound as
    /// `disposition` above.
    fn telemetry_failover(&self, pool_label: &str, reason: &'static str);

    /// Count ONE cross-protocol TRANSLATION hop `from` to `to`.
    ///
    /// Both names come from the caller's own fixed protocol vocabulary, so the emit is
    /// snapshot-independent.
    fn telemetry_translation(&self, from: &str, to: &str);

    /// Map a client-supplied model/name string to the BOUNDED `pool` metric label: the string
    /// verbatim when it names something the implementor has configured, else a fixed sentinel.
    ///
    /// Bounds the label cardinality on every finish path above. The returned slice borrows `model`
    /// (or is `'static`), so it is independent of the implementor and costs no allocation.
    fn pool_label<'a>(&self, model: &'a str) -> &'a str;
}
