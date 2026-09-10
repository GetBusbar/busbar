# Advisory: plugin ABI vtable `size` field unread — one-sided sized-struct guard (memory safety / RCE-shaped)

## Summary

The plugin hot-ABI's sized-struct guard was one-sided in two places:

1. **POD side (`field_present`).** It bounded only the shorter sender; the peer-advertised `size`
   was self-attested and trusted verbatim, so a peer that stamped an over-large `size` made every
   trailing-field probe answer `Some(..)` regardless of what was actually there.
2. **Vtable side (`PlaneHostVtable::size`).** This field was written at construction and **read by
   nothing**. `check_preamble` deliberately accepts any MINOR version, and this field was the one
   compensating control for that open window — so the window had no control at all. A plane built
   at a newer minor, handed a `*const PlaneHostVtable` from an older host, formed
   `&PlaneHostVtable` over the host's shorter allocation and loaded a trailing slot from bytes past
   the end: **a garbage function pointer, which is then called.**

This is memory-unsafety with an RCE shape (an attacker-influenced, uninitialized/out-of-bounds
value used as a function pointer and invoked) gated behind ABI minor-version skew between a plane
and its host.

## Affected versions (measured)

**None released.** `crates/busbar-plugin/src/hot/host.rs` (the vtable guard and
`PlaneHostVtable::check`) does not exist at `v1.5.5` — `git ls-tree -r v1.5.5` has no
`hot/host.rs`, `hot/pod.rs`, or `plane_host` paths at all. The whole hot-ABI plugin surface was
introduced by `6a9bd1fb6` ("busbar 1.6.0: hot-ABI foundation + plugin ABI"), unreleased 1.6.0
work, not an ancestor of `v1.5.5`.

## Fixed in

- `963be4425` (pick) / **`1e58673bf`** (landed twin, ancestor of this repo's current tip
  `ad8887f2b`) — "plugin ABI: the sized-struct guard clamps BOTH ways, and the vtable's own `size`
  is read", 2026-09-07.
- Adds `PlaneHostVtable::check`, which works off the raw pointer and never forms a `&PlaneHostVtable`
  reference before the size is validated: frozen preamble first, `size` below the frozen header is
  `SizeTooSmall`, `size` larger than this build's own struct is `SizeTooLarge` (refused, not
  clamped — a vtable slot is a called fn-pointer, not data), and a shorter size is honoured (the
  append-only rule). Clamps `field_present`'s POD-side claim to this build's own `size_of::<T>()`.
- Present on this worktree's base (`ad8887f2b`); not present on any released branch (the hot ABI
  does not exist on `origin/dev`, `origin/qa`, or `origin/main`).

## Severity (per SECURITY.md's scale)

Would be **Critical** — memory corruption leading to an attacker-influenced indirect call is
squarely the class SECURITY.md's "Escape from a dynamically loaded plugin into the host" scope
item exists for, and worse than a typical plugin escape since it does not even require a
malicious plugin, only a version-skewed one calling into an older host. As measured, it never
shipped.

## Exposure statement

The entire plugin hot-ABI is unreleased 1.6.0 work; the guard was incomplete for the whole of its
existence prior to this fix, all within development. No tagged version, including current `v1.5.5`,
ever contained this code path. **No advisory is owed to operators and no CVE is warranted.**

## Backport

None owed. No released line ever carried the plugin hot-ABI.

## Credit

Internal audit.
