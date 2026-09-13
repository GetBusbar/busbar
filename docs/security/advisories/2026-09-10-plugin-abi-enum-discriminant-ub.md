# Advisory: plugin-filled `#[repr(u8)]` enums read as raw discriminants (undefined behaviour)

## Summary

`Usage.component` and the two `framing` fields (`FramingDesc`, `JournalStreamDesc`) were
`#[repr(u8)]` enums read straight out of plane-filled memory. Because a plane fills these structs
itself, a stale build, a newer enum variant added on one side only, or a hostile cdylib writing an
out-of-range byte materialized an **invalid discriminant the instant the host read the field** —
undefined behaviour *before* the `match` runs, not merely a wrong branch taken. This is UB on
plugin-controlled input, not a logic bug.

## Affected versions (measured)

**None released.** The affected files (`crates/busbar-core/src/plane_host/govern.rs`,
`crates/busbar-core/src/plane_host/journal.rs`, `crates/busbar-plugin/src/hot/pod.rs`) do not
exist at `v1.5.5` — no `plane_host` or `hot/pod.rs` path is present in that tag's tree. This is
part of the same unreleased 1.6.0 hot-ABI foundation as the vtable-size defect
(`6a9bd1fb6`, "busbar 1.6.0: hot-ABI foundation + plugin ABI"), not an ancestor of `v1.5.5`. Note
the fix commit's own claim that "wire compatibility with published 1.5.5 plugins is preserved" —
that describes byte-layout compatibility of the `#[repr(transparent)]` carrier, not that the
vulnerable code path itself was ever live in 1.5.5; the surrounding hot-ABI dispatch code that
reads these fields does not exist in that release at all.

## Fixed in

- `e2940eb23` (pick) / **`a03fdcec6`** (landed twin, ancestor of `ad8887f2b`) — "plugin ABI: the
  three remaining plugin-filled bare enums cross as raw u8 carriers", 2026-09-07.
- Introduces `RawUsageComponent` / `RawFraming`, `#[repr(transparent)]` u8 carriers matching the
  pattern already used for every other plugin-written enum byte in this ABI
  (`RawStatus`/`RawFault`/`RawEgressKind`), decoded through checked accessors that fail closed: an
  unnamed usage component refuses the charge rather than billing a guess; an unnamed framing
  refuses `journal_register`/`journal_append` rather than reproducing a stream under the wrong
  framing. Byte layout is unchanged (`#[repr(transparent)]` preserves the image), so this is a
  read-side fix only. The commit's own sweep confirms every other plugin-reachable `#[repr(u8)]`
  enum in the ABI was already safe (host-written out-params, or already raw `u8`).
- Present on this worktree's base (`ad8887f2b`); not present on any released branch.

## Severity (per SECURITY.md's scale)

Would be **High** (UB triggerable by plugin-controlled memory — matching the "Escape from a
dynamically loaded plugin" scope item, though narrower in effect than the vtable fn-pointer defect
since a match on an invalid repr(u8) discriminant is UB but not automatically an arbitrary write
or call) had it ever shipped. As measured, it did not.

## Exposure statement

Part of the unreleased 1.6.0 hot-ABI plugin foundation for its entire existence prior to this fix.
No tagged version, including current `v1.5.5`, ever contained this code path. **No advisory is
owed to operators and no CVE is warranted.**

## Backport

None owed. No released line ever carried this code.

## Credit

Internal audit.
