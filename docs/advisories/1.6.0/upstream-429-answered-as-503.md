# Advisory: an upstream 429 is answered to the client as a 503

## Id

ADV-1.6.0-3

## Classification

Working-as-designed circuit-breaker behavior, not a defect. Recorded as an advisory because it
is surprising to a client integrator and sits inside SECURITY.md's Scope item "Denial of service
against the gateway or its circuit breaker" / "The circuit breaker mis-attributing a client
fault as an upstream fault (or vice versa)." Measured here to answer the mis-attribution
question directly: it is not a mis-attribution.

## Summary

When a single-member lane's upstream answers `429 Too Many Requests`, Busbar's own client-facing
response for that request is `503 Service Unavailable` with kind `overloaded`, not a relayed 429.
This is shipped behavior across the 1.5.x line and reproduced in 1.6.0's engine unchanged.

### Mechanism

1. `busbar-unit-breaker`'s Stage 2 classifier maps every rate-limit signal to a transient
   disposition that trips the pool cell's breaker, on the same footing as a 5xx or a timeout:

   ```
   (StatusClass::RateLimit, Disposition::TransientUpstream),
   ```

   (`crates/busbar-unit-breaker/src/classify.rs:69`, in the `DISPOSITION_TABLE`; the same file's
   module doc, `:1-19`, states this classifier was moved byte-identical from 1.5.5's
   `busbar-substrate::breaker`.)

2. `busbar-llm`'s exhaustion handler, once the pool has no eligible member left to try (a
   single-member lane trips its only member's breaker on the first 429), returns the client a
   503 in the gateway's own `overloaded` shape:

   ```rust
   pub(crate) fn handle_status_503(
       host: &Arc<dyn EngineHost>,
       cands: &[WeightedLane],
       now: u64,
       pool: &str,
       ingress_protocol: &str,
   ) -> Response {
       let retry_after = retry_after_secs(host, cands, now, pool);
       let mut resp = ingress_error(
           ingress_protocol,
           StatusCode::SERVICE_UNAVAILABLE,
           KIND_OVERLOADED,
           "The service is temporarily overloaded. Please retry shortly.",
       );
       ...
   }
   ```

   (`crates/busbar-llm/src/engine/exhaustion/mod.rs:181-199`.) A `Retry-After` header derived
   from the upstream's own signal is preserved on the response
   (`crates/busbar-llm/src/engine/exhaustion/mod.rs:186,195-198`), so a rate-aware client still
   backs off correctly even though the status code it sees is 503, not 429.

3. `wire.rs` documents the deliberate choice of the `overloaded` kind for this case specifically
   because it is the SAME kind Busbar already uses for its own 503s
   (`crates/busbar-llm/src/engine/wire.rs:171-174`), so a client cannot distinguish "the upstream
   is rate-limiting this pool" from "Busbar itself has no capacity" by response shape alone.

## Affected versions

Every 1.5.x and 1.6.0 line to date; unchanged by the 1.6.0 plane-extraction work (the classifier
was carried byte-identical; see Evidence).

## Impact

A client that specifically branches on HTTP 429 (e.g., to apply provider-specific backoff, or to
surface a "rate limited" state distinct from "service unavailable" to its own end users) will not
see that status from Busbar for an upstream rate limit — it will see 503. The `Retry-After`
header is present in both cases, so backoff timing is preserved; only the status-code semantics
differ from a direct-to-provider integration. This is not a mis-attribution in the circuit
breaker's own terms: a rate limit IS treated as transient-upstream (correctly distinguished from
a client fault, which would not penalize the lane, and from a hard-down credential/billing
failure, which would sticky the lane), and the choice of client-facing status code is a separate,
deliberate design decision layered on top of a correct classification.

## Severity per SECURITY.md

Not a vulnerability under SECURITY.md's Scope list. It is shipped, intended behavior: the
breaker's classification of `RateLimit -> TransientUpstream` is correct (see Mechanism), and the
503-with-Retry-After response is a documented design choice (`wire.rs:171-174`), not an
unattributed fault. No severity band applies; recorded as an advisory for operator/client-
integrator awareness, not as a fix-tracked defect.

## Evidence

- `crates/busbar-unit-breaker/src/classify.rs:69` — `StatusClass::RateLimit` maps to
  `Disposition::TransientUpstream` in `DISPOSITION_TABLE`.
- `crates/busbar-llm/src/engine/exhaustion/mod.rs:181-199` — `handle_status_503`, the client-
  facing 503 `overloaded` response with `Retry-After`.
- `crates/busbar-llm/src/engine/wire.rs:171-174` — comment explaining the deliberate reuse of the
  `overloaded` kind for a genuine upstream 503/exhaustion terminal.
- `crates/busbar-llm/src/engine/health.rs:259,440,443,460` — `TransientUpstream` handling in the
  health/breaker-write path, consistent with the classifier.
- Internal audit ledger (`gate/held.txt`): "upstream 429 answers the client 503 overloaded
  (breaker parks the single-member lane) — shipped behaviour, not a money-path change; advisory
  candidate at the tag, owner to be told."

## Remediation / operator action

No code change proposed. An operator or client integrator that needs to distinguish
provider-rate-limit from gateway-exhaustion should key off the `Retry-After` header's presence
and the response `kind` (`overloaded`) rather than the HTTP status code, or configure a
multi-member pool so a single upstream's rate limit does not exhaust the pool. If distinguishing
429-from-upstream as a first-class client-visible status is wanted, that is a wire-contract
change scoped beyond this advisory (it would mean relaying upstream status codes verbatim,
which the gateway does not do today by design — see `wire.rs`).

## Backport

None proposed; not a defect.

## Credit

Internal audit.
