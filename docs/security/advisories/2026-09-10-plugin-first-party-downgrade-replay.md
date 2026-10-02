> **STOP: owner decision on disclosure.** Shipped in **every release from 1.5.0 through the
> current published 1.5.5**, for the whole lifetime of those lines, per the fix commit's own
> words. This advisory is written in-tree only. Do not publish, file a GitHub Security Advisory,
> or request a CVE until an owner has set severity, affected-version scope, and disclosure timing
> per SECURITY.md.

# Advisory: signed-downgrade replay of first-party plugins (anti-downgrade control absent, contrary to documentation)

## Summary

`docs/plugins.md` security-model item 3 has, since before 1.5.0, promised: *"A validly-signed but
OLD first-party release cannot be replayed."* It could be. The control that backed that claim —
flooring first-party plugins at the running binary's version — was removed before 1.5.0 shipped
(correctly: first-party plugins version on independent lines from the engine, e.g. 1.0.x
stores/auth/hooks under a 1.5.x engine, so a binary-version floor rejected every correctly-signed
current release). **Nothing replaced it**, and `TrustPolicy::evaluate` short-circuited on an empty
floor set. On a default deployment the first-party floor set was `{}` and the anti-downgrade branch
never fired.

The attack, as the fix commit states it: an attacker with **write access to `plugins.dir`** —
precisely the threat the plugin-signing gate exists to contain — could replace the current tarball
with a *genuine*, busbar-signed **older** first-party release carrying a known, already-fixed
defect. It verifies against the embedded release key and loads as `Trusted { first_party: true }`,
labeled `first-party` in the catalog, **with no warning** — silently reintroducing whatever the
older release was vulnerable to.

Four contract sources asserted the control existed while it did not: `docs/plugins.md` item 3,
`evaluate`'s own doc comment ("sixty lines above the body that removed it"), the
`TrustPolicy::{first_party_floors, binary_version}` field docs, and two comments in
`config/mod.rs`. Operators sizing their own risk against `plugins.dir` write access were told a
control was in place that was not.

## Affected versions (measured)

**1.5.0 through 1.5.5 (current published release), for the entire duration.** Per the fix
commit's own description, the binary-version floor was removed *"before 1.5.0 shipped"* and never
replaced until this fix — i.e. every tagged 1.5.x release, including `v1.5.5`
(`testing/shadow-oracle/golden/1.5.5/meta.json`, `binary_sha256: 84bde0a0…`), shipped with an
empty first-party floor set and a no-op anti-downgrade branch. `docs/plugins.md` promised the
control for that entire window.

Precondition: write access to `plugins.dir`. This is the exact threat model the plugin-signing
gate is built for (SECURITY.md's own framing of "Escape from a dynamically loaded plugin" implies
the artifact on disk is the trust boundary being defended); it is not a remote, credential-free
attack, but it is a documented control silently absent for the threat it was written against.

## Fixed in

- `7e3876ed6` (pick) / **`7f8782f74`** (landed twin — ancestor of this repo's current tip
  `ad8887f2b`) — "plugins: the first-party anti-downgrade floor docs/plugins.md promises now
  exists", 2026-09-07.
- Replaces the binary-version floor with a **per-plugin-name high-water mark**: the highest
  version of that plugin name this deployment has itself seen and loaded, raised only by a load
  busbar itself performed, never lowered automatically. A name never loaded carries no floor (a
  first install is not a downgrade). `plugins.min_versions` pins additional floors by name.
  Deliberate rollback goes through the already-audited `plugins.rollback` admin action, which
  replaces the automatic floor for that name. Fails soft (`BUSBAR-6011`) on a damaged floor file
  rather than refusing to boot, on the stated reasoning that refusing to boot over one corrupt JSON
  file "would let anyone able to corrupt one JSON file take the node down, which is worse than the
  window this control closes."
- Present on this worktree's base (`ad8887f2b`) and `origin/integration/oracle-phase0`.
  **Backport-branch status to `dev`/`qa`/`main` not verified here** — flag for owner follow-up
  alongside the disclosure decision, since the fix is architecturally independent of the 1.6.0
  plane extraction (it touches `plugin-sign`, `plugin-loader`, `preflight.rs`, `config/mod.rs`,
  `docs/plugins.md`) and appears portable to the 1.5.x line without a forward-port blocker like
  item (b) below has.

## Severity (per SECURITY.md's scale)

**High.** Matches SECURITY.md's own scope item "Escape from a dynamically loaded plugin into the
host or another plane" in spirit — a documented anti-downgrade control did not exist, permitting a
believed-current, signature-verified plugin to actually be a known-vulnerable older release,
loaded with no warning. Not Critical only because it requires filesystem write access to
`plugins.dir`, which SECURITY.md's "Out of scope" section treats as a step up from a fully remote
attacker; still, that write access is exactly the threat the signing gate exists for, so a silent
gap here defeats the gate's own stated purpose for its whole lifetime to date.

## Exposure statement

**The absent control shipped in every 1.5.x release to date, and `docs/plugins.md` affirmatively
misdescribed the product for that whole window.** This is not a pre-release-only finding. A fix
exists and appears to be a clean, standalone unit (not entangled with unreleased 1.6.0
architecture the way the rate-limiter fix is), which should make a backport tractable once an
owner decides on disclosure and timing.

## What the docs should have said (1.5.0–1.5.5)

`docs/plugins.md` item 3 claimed, without qualification, that a validly-signed but old first-party
release "cannot be replayed." For 1.5.0–1.5.5 the accurate statement would have been closer to:
*"First-party plugins are not currently floored against replay of an older signed release; an
operator who cannot fully trust the integrity of `plugins.dir` should treat a compromise of that
directory as capable of reintroducing a previously fixed first-party plugin defect. Track this as a
gap, not a mitigated risk."* That the actual document said the opposite is itself part of what the
owner needs to weigh in the disclosure decision — this was not merely an unmitigated risk, it was a
misrepresented one.

## Backport

**Likely owed, pending owner decision on severity and disclosure timing.** Per SECURITY.md, High
severity backports to the latest two supported minor lines. Recommend the owner also decide
whether corrected historical language is needed in release notes for 1.5.0–1.5.5, given the
documentation itself was wrong, not merely silent.

## Credit

Internal audit.
