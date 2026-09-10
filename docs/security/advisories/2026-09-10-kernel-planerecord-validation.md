# Advisory: `busbar-kernel` PlaneRecord legs previously ran without a single validation chokepoint

## Summary

`crates/busbar-kernel/src/pump.rs` gained `run_record_leg` / `run_record_plan`, the one runner of a
`PlaneRecord` route-plan leg: schema declared by the calling plane, operation declared by that
schema, and body size within `MAX_RECORD_BYTES` — all checked before the sink is ever called, in
the architecture's own `PlaneRecord` order. Before this commit, no such chokepoint existed in the
kernel at all: `busbar-kernel` and the `PlaneRecord` leg concept are both new to the 1.6.0
plane-extraction, so there was no prior kernel code path to bypass a check in — this is the check
being built for the first time, not restored.

## Affected versions (measured)

**None released.** `busbar-kernel` does not exist at `v1.5.5`:
`git ls-tree -r v1.5.5 -- crates/busbar-kernel` is empty. The crate was introduced by `ad49838bf`
("busbar-kernel: the Teller loop, pump, in-flight table, recovery, slices, registry, grammars"),
part of the unreleased 1.6.0 plane-extraction work, and is not an ancestor of `v1.5.5`.

## Fixed in

- `fcfcafb16` — "kernel: the one runner of PlaneRecord legs — schema, op and size validated before
  the sink" (cherry-picked from `190f242f7`), 2026-09-07.
- Present on `origin/integration/oracle-phase0` and its `keep-*` descendants. Not applicable to any
  released line; not present on `origin/dev`, `origin/qa`, or `origin/main`.

## Severity (per SECURITY.md's scale)

**Low**, as measured: this is new-code hardening added before the kernel's first release, not a
regression against a shipped validation path. Had `busbar-kernel` shipped without it, an
unvalidated record leg naming an undeclared schema/operation or an oversized body would have
reached the sink directly, which would raise this substantially — but that configuration never
shipped.

## Exposure statement

The kernel and the `PlaneRecord` leg abstraction are both unreleased. No tagged version ever ran
`busbar-kernel` without this validation. **No advisory is owed to operators and no CVE is
warranted.**

## Backport

None owed. No released line ever carried `busbar-kernel`.

## Credit

Internal audit.
