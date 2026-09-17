# Advisory: admin scope port (`busbar-unit-scope::admin_required_scope`) drifted from the enforced matrix on two rows

## Summary

`busbar-unit-scope::admin_required_scope` documented itself as a verbatim, behaviourally-identical
port of the engine's enforced `(method, path) -> Scope` matrix
(`busbar_core::admin::v1::contract::required_scope`), with only a representational change (`method`
as a plain string instead of `axum::http::Method`). It was not verbatim, in two places:

1. **The method comparison folded case.** An HTTP method is a case-sensitive token — `get` is not
   `GET`, it is a distinct extension method — but the port compared case-insensitively, so a
   mutation-shaped path addressed with a lowercase method spelling (an extension method nothing
   routes) answered `read-only` instead of the enforced matrix's `full`.
2. **The two stateless dry-run paths (`/config/validate`, `/plugins/inspect`) were made conditional
   on `POST`.** The enforced matrix keys them on path alone, so the port required `full` for every
   other mutation-shaped method addressed at those two paths, where the enforced matrix allows
   `read-only`.

The two matrices were **both live at once** on this development branch: the engine's is what the
one enforcement chokepoint every admin request crosses (`auth::auth_middleware`) spent, and the
port is what the (also unreleased) kernel loop's APPROVE step spent
(`units_admin::approve`, `admin_mount::declared_scope`). Nothing routes a request with a
case-folded or otherwise nonstandard method token, so a request that reached either gap ended at a
405 whichever answer it got — but the two answers had to agree regardless, since the same question
asked twice must not have two answers. The port is corrected to the enforced matrix exactly, proven
by a cross-product cell that walks every path the frozen 1.5.5 table names against every method a
socket can carry (including the extension methods nothing routes), and by a cell that reads
`x-busbar-required-scope` off the SERVED document (the inflated embedded gzip, not a freshly
generated one) and checks every published bar against the matrix the node spends.

## Affected versions (measured)

**None released.** `busbar-unit-scope` does not exist at any of the five shipped 1.5.x tags:

```
v1.5.0: 0 matches for `unit-scope` in `git ls-tree -r <tag>`
v1.5.1: 0
v1.5.2: 0
v1.5.3: 0
v1.5.4: 0
v1.5.5: 0
```

At `v1.5.5`, the sole scope matrix is `crates/busbar/src/admin/v1/contract/mod.rs::required_scope`,
consumed directly by `auth::auth_middleware` (`crates/busbar/src/auth/mod.rs:1310`). It compares the
method against the `axum::http::Method::GET`/`HEAD` enum variants (not a string, so no case-fold is
possible) and keys the two dry-run paths on path alone (no `POST` conditional). **No admin operation
was reachable under a mismatched scope in 1.5.0–1.5.5**, because the code that could mismatch did
not exist: `busbar-unit-scope` was introduced by `a958271eb` as part of the unreleased 1.6.0
plane-extraction, strictly after `v1.5.5`, and is not an ancestor of any 1.5.x tag.

Within the unreleased 1.6.0 development history itself, the drift was also never live at the one
real enforcement chokepoint: `auth::auth_middleware` did not call
`busbar_unit_scope::admin_required_scope` until `7db466594`, and that same commit is the one that
retired the engine's own matrix in the port's favor — by which point the port had already been
corrected by the immediately preceding `16fc95e66`. `auth_middleware` never spent the buggy version
at any commit in this repo's history. The only consumer of the buggy version, for the whole of its
existence, was the kernel loop's own (also unreleased, not yet routed) APPROVE step.

## Fixed in

- `16fc95e66` — "[SEAM] one authorization matrix, and the scope unit's port is the enforced one
  exactly" — corrects the method comparison to an exact (case-sensitive) match and keys the two
  dry-run paths on path alone, red-first against a cross-product cell over the frozen 1.5.5 path
  table x every method a socket can carry, plus an ungated cell pinning `x-busbar-required-scope` on
  the served document to the unit's matrix.
- `7db4665944` — "DELETE busbar-core/src/admin/v1/contract's Scope, Grants and required_scope: one
  authorization matrix, and the APPROVE step's crate holds it" — deletes the engine's now-redundant
  matrix and repoints `auth::auth_middleware`, the served `x-busbar-required-scope` stamp, and the
  `AdminError::Forbidden { needed }` taxonomy onto the (already-corrected) unit's matrix, so there is
  exactly one matrix from this commit forward.
- Present on this worktree's base. Not applicable to any released line: `busbar-unit-scope` is not
  present on `origin/dev`, `origin/qa`, or `origin/main`.

## Severity (per SECURITY.md's scale)

**Low**, as measured. This is new-code hardening caught while building the unreleased 1.6.0
kernel/plane-extraction's admin-scope port, not a regression against a shipped enforcement path:
`auth::auth_middleware` — the one chokepoint every admin request crosses — never spent the buggy
matrix at any commit, and the standalone drifted period predates any released tag by construction.
Had the case-insensitive fold shipped as the live enforcement matrix, and had routing ever admitted
a lowercase-method request, it would have let a `read-only`-scoped caller reach a mutation-classed
admin operation over an extension-method spelling — an authorization-bypass shape matching
SECURITY.md's "Admin-plane isolation" and front-door-auth scope items, which would raise this to
at least **High**. As measured, that configuration never existed: nothing routes the affected method
tokens, the buggy version was never the enforcing one, and no released version ever carried the
port at all.

## Exposure statement

`busbar-unit-scope` is unreleased 1.6.0 work. No tagged version, including current `v1.5.5`, ever
contained this crate or its admin-scope port, in either its drifted or corrected form. **No
advisory is owed to operators and no CVE is warranted.**

## Backport

None owed. No released line ever carried `busbar-unit-scope`.

## Credit

Internal audit.
