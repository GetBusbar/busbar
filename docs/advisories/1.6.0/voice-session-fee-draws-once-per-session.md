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

`busbar-kernel`'s flat per-session fee is decided by `fee_count` (`crates/busbar-kernel/src/teller.rs`),
which requires three conditions before the fee is eligible to draw:

```
let eligible = evidence.client_open_or_one_shot
    && evidence.selected_upstream
    && evidence.relayed_first_response_frame;
```

(`crates/busbar-kernel/src/teller.rs:415-417`, doc comment at `:401-410`.)

`relayed_first_response_frame` (`FeeEvidence` field, `crates/busbar-kernel/src/teller.rs:392`) is
supplied per composed leg by the voice/streams root wiring
(`crates/busbar/src/root/units_voice.rs:1982,1988`). On every shipped 1.5.5 voice composition, the
only frame relay path taken was `Detached`, which never sets this flag — so it is `false` on
every real session, and the configured flat session fee is never eligible to draw. Two existing
test cells asserted `fee == 1` against a fixture that does not correspond to any shipped
composition; against the actual shipped composition, the fee is `0`.

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

Once a leg that genuinely opens is mounted (the dialect table gains an explicit `opening_frame`
declaration, consumed by the neutral plane at `open_session`, so the root no longer originates a
protocol event itself), `relayed_first_response_frame` becomes `true` for a real opened leg and
the configured fee draws, as configured, once per session. This is a byte change relative to
every shipped 1.5.x binary, by design: a configured fee that a defect prevented from ever drawing
was the defect, not a lower price.

## Ruling

Integrator ruling (owner may override): the fee draws once per session when the leg opens, as
configured. No backport to 1.5.x is proposed — turning on a previously-inert charge is a
forward-only behavior change appropriate to a minor version bump with release-note disclosure,
not a patch-release backport.

## Evidence

- `crates/busbar-kernel/src/teller.rs:392` — `relayed_first_response_frame` field on `FeeEvidence`.
- `crates/busbar-kernel/src/teller.rs:401-417` — `fee_count`, the eligibility gate and its doc
  comment.
- `crates/busbar/src/root/units_voice.rs:1982,1988` — the root's leg composition supplying the
  flag, `Detached` being the only path exercised in shipped compositions.
- Internal audit ledger (`gate/held.txt`): "the per-session flat fee needs
  relayed_first_response_frame, which has been FALSE on every shipped composition (the only
  frame relay was Detached) — 1.5.5 never draws the configured voice session fee; two cells
  asserting fee==1 read an unshipped fixture and now assert the shipped 0."

## Remediation / operator action

No action required to keep current 1.5.x billing behavior other than staying on 1.5.x. Upgrading
to 1.6.0 with an existing `session_fee:` configuration will start collecting that fee; an
operator who set the value without expecting it to be charged should review it before upgrading.

## Commits

Landed on the `integration/plane-extraction` line as part of the voice-leg opening-frame work
(dialect `opening_frame` declaration + root leg composition). Queued sha not yet assigned in this
worktree at the time of writing (worktree tip `143db6db6`); see the ledger line above for the
harvested commit reference (`b289f2ef3`) once it lands on `dev`.

## Credit

Internal audit.
