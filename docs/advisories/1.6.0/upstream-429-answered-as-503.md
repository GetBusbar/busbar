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
This is shipped behavior across the 1.5.x line and is the 1.6.0 behavior too.

### Mechanism

1. The breaker's classifier maps every rate-limit signal to the transient-upstream disposition, on the
   same footing as a 5xx or a timeout, so a 429 trips the pool cell's breaker
   (`classify` in `crates/busbar-kernel-breaker/src/classify.rs`: `WireFault::RateLimit` and
   `WireFault::Transient` both yield `Disposition::TransientUpstream`; the rate-limit outcome keeps the
   upstream's `retry_after`, `classify_upstream` in `crates/busbar-kernel-breaker/src/port.rs`).
2. Once the pool has no eligible member left to try (a single-member lane trips its only member's
   breaker on the first 429), the client is answered with Busbar's own `overloaded` kind and status 503
   rather than a relayed 429, with a `Retry-After` taken from the upstream's own signal. The kernel
   uses the same kind for its own capacity refusals (`KIND_OVERLOADED`,
   `crates/busbar-kernel/src/ingress/mod.rs`), so a client cannot tell "the upstream is rate-limiting
   this pool" from "Busbar itself has no capacity" by response shape alone. The exhaustion answer for
   an LLM lane is built by the LLM plane plugin; its own documentation is authoritative for the exact
   body.

## Affected versions

Every 1.5.x release and 1.6.0.

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
503-with-Retry-After response is a documented design choice (the shared `overloaded` kind), not an
unattributed fault. No severity band applies; recorded as an advisory for operator/client-
integrator awareness, not as a fix-tracked defect.

## Evidence

- `crates/busbar-kernel-breaker/src/classify.rs`: `classify` maps `WireFault::RateLimit` to
  `Disposition::TransientUpstream`.
- `crates/busbar-kernel-breaker/src/port.rs`: `classify_upstream` carries the upstream's `retry_after`
  into `Outcome::RateLimit`.
- `crates/busbar-kernel/src/ingress/mod.rs`: the kernel's own 503 `overloaded` refusals use the same
  kind.
- The client-facing 503 for an exhausted LLM lane is the LLM plane plugin's; it was not re-measured
  from this tree.

## Remediation / operator action

No code change proposed. An operator or client integrator that needs to distinguish
provider-rate-limit from gateway-exhaustion should key off the `Retry-After` header's presence
and the response `kind` (`overloaded`) rather than the HTTP status code, or configure a
multi-member pool so a single upstream's rate limit does not exhaust the pool. If distinguishing
429-from-upstream as a first-class client-visible status is wanted, that is a wire-contract
change scoped beyond this advisory (it would mean relaying upstream status codes verbatim,
which the gateway does not do today by design).

## Backport

None proposed; not a defect.

## Credit

Internal audit.
