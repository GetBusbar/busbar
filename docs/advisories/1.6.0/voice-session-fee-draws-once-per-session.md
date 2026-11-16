# Advisory: the configured voice/streams session fee now draws once per session

## Id

ADV-1.6.0-1

## Classification

Not a SECURITY.md-scoped vulnerability. This is a shipped-behavior / billing-correctness
advisory: a configured fee that was defined but never charged in 1.5.5 now charges, in 1.6.0,
exactly as configured. SECURITY.md's severity scale (Critical/High/Medium/Low) is written for
the vulnerability classes in its Scope section and is not applicable here; this is disclosed at
the tag on the same "tell the operator what byte changed and why" basis as a Security entry.

## Summary

The configured flat per-session fee (`session_fee` on a rate card) was defined but never drawn on the
1.5.x voice/streams compositions: the leg that carries a session was composed so that the fee's
eligibility evidence (a response frame relayed from the selected upstream on an open leg) was never
set, so the fee was never eligible to draw and a session priced at `0`. 1.6.0 prices it: a session
that the far end answers draws the fee once, and `/admin/usage` agrees with the budget book.

## Affected versions

1.5.x (measured: 1.5.5, the current published version, and by inspection of the same composition
path in earlier 1.5.x tags — no earlier tag composes the leg any differently). The configured
`session_fee` billing key has been present and non-functional for the entire 1.5.x line.

## Impact

An operator who configured a per-session voice fee has never actually collected it. This is a
revenue-recognition gap for the operator, not a customer-facing overcharge, and it involves no
credential or data exposure — it is out of SECURITY.md's Scope list entirely (no confidentiality,
integrity, or availability impact; the defect makes Busbar collect *less* than configured, not
more).

## 1.6.0 change

In 1.6.0 the session leg is a plane-owned exchange and the fee draws, as configured, once per
session answered by the far end (the streaming plane's own documentation states its session
semantics). This is a byte change relative to
every shipped 1.5.x binary, by design: a configured fee that a defect prevented from ever drawing
was the defect, not a lower price.

## Ruling

Integrator ruling (owner may override): the fee draws once per session when the leg opens, as
configured. No backport to 1.5.x is proposed — turning on a previously-inert charge is a
forward-only behavior change appropriate to a minor version bump with release-note disclosure,
not a patch-release backport.

## Evidence

- `two_sessions_price_their_session_fee_on_admin_usage` in
  `crates/busbar/src/tests/admin_application/service_plane_usage.rs`: two sessions at a session fee of
  40 give a budget book of 80, and `/admin/usage` agrees (before the change it read 0).
- `crates/busbar-kernel-ledger/src/cost/rate.rs`: `session_fee` on the rate card (default 0, so a
  card that sets none charges none).
- The 1.5.x behaviour (the fee never drawing) was measured against the published 1.5.5 binary and
  is not reproducible from this tree.

## Remediation / operator action

No action required to keep current 1.5.x billing behavior other than staying on 1.5.x. Upgrading
to 1.6.0 with an existing `session_fee:` configuration will start collecting that fee; an
operator who set the value without expecting it to be charged should review it before upgrading.

## Credit

Internal audit.
