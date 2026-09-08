# control-oauth2 — the OAuth 2.1 issuer as a CONTROL surface

**Status: the module map for the move of `busbar_core::oauth_as` into `busbar-control-oauth2`.**
Base commit `79c56ef31`. The rule this is judged against is the control-kind row and the
control-route rule in `docs/design/PLUGIN-TREE.md` — *a control surface declares routes as data; no
plugin names a transport* — written by a separate unit; nothing here edits `PLUGIN-TREE.md` or
`kind-isolation`.

## 1. The ruling, in the shape it lands

Two families of served things.

| | DATA PLANE | CONTROL SURFACE |
|---|---|---|
| examples | `llm`, `mcp`, `a2a`, `streams` | the admin API (`busbar-control-admin`, R7); the OAuth 2.1 issuer (this) |
| metered | yes — the full step list | **no** |
| the path it runs | decode · authenticate · verify · approve · admit · route · meter · audit · encode | **verify · admit · audit · answer** |
| how it is served | `PlaneDecl::routes` → `PlaneRouteSpec` | `ControlDecl::routes` → `ControlRouteSpec` |
| what it declares | meter class, scope kind, audit kind, audience binding, claim ladder | a key, and a route table |

`oauth_as` is squarely the second: nothing it does is priced, nothing it does reaches upstream, and
every one of its endpoints is a way of reaching busbar's controls or obtaining a credential rather
than a way of spending money through it.

## 2. The module map

`busbar-core/src/oauth_as/` was 2,388 source lines across 8 files plus 1,989 test lines. After the
move it is **432 source lines across 3 files** — a delta of **−1,956 source lines** — and the surface
crate is 2,575 source lines plus 852 test lines.

| was | is | half | why |
|---|---|---|---|
| `oauth_as/config.rs` (283) | `busbar-control-oauth2/src/config.rs` | **issuing** | the `oauth_as:` grammar and every boot refusal. Moved verbatim. |
| `oauth_as/signer.rs` (231) | `.../src/signer.rs` | **issuing** | ES256 over `ring`, and the RFC 7518 §3.4 fixed-width `r‖s` trap. Moved verbatim. |
| `oauth_as/consent.rs` (281) | `.../src/consent.rs` | **issuing** | the sessions, the one-shot approval spend, the two resolvers `oauth-as` calls back into. Moved verbatim. |
| `oauth_as/policy.rs` (125) | `.../src/policy.rs` | **issuing** | the registration ceiling a registrant cannot move. Moved verbatim. |
| `oauth_as/cimd.rs` (616) | `.../src/cimd.rs` (537) | **issuing**, minus the fetch | the document checks and the `Storage::get_client` seam. The guarded fetch was cut out (row below). |
| `oauth_as/plane.rs` (258) | `.../src/surface.rs` | **issuing** | the running server. `AsPlane` → `OAuth2Control`; `build` gained the fetch seam, `spawn_sweeper` gained a fault sink. |
| `oauth_as/routes.rs` (503) | `.../src/routes.rs` (504) | **routes → bodies** | the `mount` fn is GONE. What is left is the three bodies. |
| — | `.../src/claims.rs` (189) | **routes → DATA** | **NEW.** The seven-row table, as values. |
| — | `.../src/meta.rs` (42) | declaration | **NEW.** `KEY`, `DIALECT`, `CONTROL_ABI`, `CONTROL_PATH`, `CONFIG_SECTION`. |
| — | `.../src/lib.rs` (103) | entry | **NEW.** The single `pub` entry and the module list. |
| `oauth_as/cimd.rs::GuardedFetch` | `busbar-core/src/oauth_as/fetch.rs` (173) | **verification/node** | **STAYED.** See §4. |
| `oauth_as/mod.rs` (91) | `busbar-core/src/oauth_as/mod.rs` (114) | shim | the transitional re-exports + the two whole-composition proofs. |
| — | `busbar-core/src/oauth_as/control.rs` (145) | mount translation | **NEW.** Declared table → neutral seam. See §5. |

### What was already verification, and is therefore neither moved nor duplicated

The brief asked which parts are verification already living in `busbar-unit-auth`, to be repointed
and deleted. **The answer is none, and that is a finding rather than a convenience.**
`busbar-unit-auth` carries the credential chain, the credential cache, the carriers, the challenge
and the claim ladder — it has **no signer and no ES256 anywhere in it** (`grep -n 'Es256\|Signer\|ring::' crates/busbar-unit-auth/src/*.rs` returns nothing). The tree's only ES256
signer is the one in `oauth_as/signer.rs`, and the only other JWS signer is `egress_auth`'s RS256.
So "ONE signer = busbar-unit-auth's" is not a repoint that was available: there is nothing there to
repoint onto. It is carried as an unproven item (§7).

What IS shared and was not duplicated: the CONSENT ROUTE's admission. The issuer does not
authenticate the operator itself — the row declares `Bar::Operator`, the composition records
`RouteAuth::Admin`, and the node's existing admin chain identifies the caller before the body runs.
That is the one place this surface could have grown a second opinion about who an operator is, and
it does not.

## 3. The routes, declared as data

`busbar-control-oauth2/src/claims.rs`:

```rust
pub struct ControlRoute { endpoint: Endpoint, method: Method, bar: Bar, handler: Handler }
pub const ROUTES: &[ControlRoute] = &[ /* seven rows */ ];
```

All four fields are VALUES. The rows carry no path: a path on this surface is derived from the
operator's `issuer` (`Endpoint::path_of`), because a tenant-prefixed issuer mounts its endpoints
under that prefix and a table with literals would be right for one deployment.

| endpoint | method | bar | body |
|---|---|---|---|
| `/.well-known/oauth-authorization-server{issuer_path}` | GET | Open | forward |
| `{issuer_path}/jwks` | GET | Open | forward |
| `{issuer_path}/authorize` | GET | Open | forward |
| `{issuer_path}/token` | POST | Open | forward |
| `{issuer_path}/consent` | GET | **Operator** | consent screen |
| `{issuer_path}/consent` | POST | **Operator** | consent submit |
| `{issuer_path}/register` | POST | Open | forward |

`Bar::Open` on five rows is not an absence of authentication; it is authentication that belongs to a
different protocol (OAuth's own client authentication, which `oauth-as` performs) and is done by the
library that implements it.

## 4. The one thing that stayed, and why

`GuardedFetch` — the Client ID Metadata Document fetch — is in `busbar-core/src/oauth_as/fetch.rs`.

The CIMD URL is attacker-supplied on an endpoint that takes no credential. What makes that fetch
safe is `net_guard`'s resolve-then-pin: structural name refusals, exactly one resolution, every
answered address judged, an unconditional cloud-metadata arm no knob can move, then a pin so the
socket goes to the judged address while the `Host` header, the TLS SNI and the certificate name check
stay on the NAME. **That control belongs to the node and must have exactly one copy** — a drifted
copy of this same guard was a live cloud-metadata bypass on the MCP plane.

So the split is: *what a client metadata document is* is the protocol's, and *where a socket may go*
is the node's. The surface declares the seam (`CimdFetch`) and its own bounds (`MAX_DOCUMENT_BYTES`
= 5 KB, `FETCH_TIMEOUT` = 10 s, no redirects); the composition installs the mechanism.
`CimdFetch::names_a_document` is on the same seam for the same reason: deciding a `client_id` parses
as an authority you could dial is the guard's grammar (`net_guard::split_url`), not an authorization
server's.

The sweeper's diagnostics split the same way. `OAUTH_AS_SWEEP_FAILED` is a registered code an
operator greps for; a control surface stamping one would be minting node vocabulary from outside the
node. `spawn_sweeper` now reports `SweepFault { error, first }` and `appbuild` says it in the node's
words, at the same two levels, with the same warn-once-on-transition latch.

## 5. The control-route seam the composition uses — NAMED

**`busbar_substrate::control_routes`**: `ControlRouteSpec`, `ControlReqCtx`, `ControlDecl`,
`install_control_surfaces` / `control_decls`. Mounted by `busbar_core::router::mount_control_route`.

**It is new, and the brief's question — "is the mount admin uses admin-shaped?" — has a sharp
answer: yes, and reusing it would have been a security regression.** The mount the root uses for the
admin surface is `root::units_admin::admin_mount::mount`: it WRAPS the finished router in a fallback
that claims `busbar_contract::surface::ADMIN_PREFIX` and passes everything else through. That
wrapper sits **outside the node's auth middleware**, so a route mounted through it carries no row in
`CoreRouteTable` and gets no declared admission bar. The admin API can afford that because it
re-authenticates every request in its own kernel steps. The OAuth issuer cannot: `/consent`'s whole
design is that the operator has *already* been identified by the node's admin chain before the body
runs, and moving it outside the middleware would either drop that bar or force the surface to grow
the second opinion it was built not to have. So the admin wrapper was **not** made generic, and the
reason is recorded in `control_routes.rs`'s header so the next reader does not "unify" the two.

What the new seam does instead is call the **same `CoreRouter::route`** a plane route calls, with the
spec's own `(path, method, auth)`. The route-table row is recorded by the same act, so no admission
bar moved. That is the property the whole extraction rests on, and the byte-identity battery is what
checks it end to end.

`ControlDecl` has two fields. That is not an omission: it is the difference between a control surface
and a plane written down.

**Registration.** `main::register_control_surfaces()` — the composition root's one write into the
control axis, in the same boot slot as `register_planes()`. **Unconditional**, because `oauth_as:`
has never had a feature gate: it was a non-optional dependency of `busbar-core` with no `#[cfg]` on
its module, so the shipped binary could always honour an `oauth_as:` block, and what decided whether
anything was served was the config. A feature gate now would be a behaviour change wearing a
refactor's clothes. Posture identical.

## 6. Config, and the path used

`OauthAsCfg` / `AsIdentity` live in **`busbar-control-oauth2::config`** and are read by
`busbar-core` through the transitional re-export `crate::oauth_as::config`.

**The config home used is neither of the two the brief named.** `busbar-substrate::config` was not
used, because moving the lowering there would have required `busbar-substrate` to name the surface
crate — an edge from the substrate up into a plugin, which is worse than the edge being removed. And
`busbar-core-config` does not exist in this tree yet (the crate the parallel unit is creating). So
the types live with the surface that defines them, and `busbar-core` keeps the *lowering* — the
`resolve` call, the `prepass` lift and the `config_validate::secret_refs` destructure — which is the
one edge core still has to this crate, named in §7.

## 7. Staging: what is done, and what is owed

**Done.** The issuing half and the routes are a control crate; the routes are declared as data; the
composition mounts them through a generic seam; core's oauth2-specific mount is deleted and there is
ONE copy; every response is byte-identical.

**Owed, and each blocked on something outside this unit:**

1. **`Kind::Control`, `CONTROL_ABI`, `ControlMeta` in `busbar-contract`.** The contract's `Kind` enum
   has eight variants and none is `Control`; the crate carries an ABI floor for two kinds only
   (`STORE_ABI`, `TRANSPORT_ABI`). So `busbar-control-oauth2` **cannot implement
   `busbar_contract::plugin::Plugin`** and declares `meta::CONTROL_ABI = 1` locally instead. Recorded
   as an ignored, panicking test in `src/tests/conformance.rs` rather than as a comment.
2. **The config lowering → the config home.** While `busbar-core` lowers `oauth_as:`, it names
   `busbar-control-oauth2` as a normal dependency. Core names no route, path or handler through that
   edge, but the edge is real and is the reason `oauth_as/control.rs` (the declared-table → neutral-
   seam translation) is in core rather than in the root: core's own mount proof needs the decl, and a
   second copy written for the proof would be exactly the drift that file's tests exist to catch.
   Both move to the root together.
3. **The signer.** `busbar-unit-auth` has no signer to be the "ONE signer" (§2). Either the ES256
   signer moves into `busbar-unit-auth` and both `oauth_as` and `egress_auth`'s JWS path reach it
   through the unit's public seam, or the ruling's "one signer" is restated. Not decidable inside
   this unit.
4. **`kind-isolation` does not know this crate.** The gate is specified in `PLUGIN-TREE.md`
   Appendix G but is **not implemented** — `xtask/src/gates/` has no `kind_isolation.rs` and the
   28-gate registration list has no `kind-isolation` entry. `qa/construction.toml`'s
   `[gate.plugin_kinds]` classifies by directory glob and has no `crates/busbar-control-*` row.
   Not edited here, per the brief.
5. **`busbar-control-admin`.** The admin plane's rename and its move onto this seam is R7.
