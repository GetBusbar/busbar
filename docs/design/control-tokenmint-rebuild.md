# control-tokenmint rebuild — core's `oauth_as` as a CONTROL-kind plugin

**Status: CUT OVER AND JUDGED.** The seven routes are served by `busbar-control-tokenmint` through a
registry row the composition root owns; `busbar_core::oauth_as`'s served half is deleted; the
byte-identity judge is GREEN on the REBUILT route — 29 cells, 0 diverging, against a recording taken
on the base binary. Base `origin/keep-control-oauth2` @ d7436a8e0.

## What is being rebuilt, exactly (measured, not the brief's list)

`busbar-core/src/oauth_as/` serves SEVEN routes, derived from the operator's `issuer`: `GET
/.well-known/oauth-authorization-server{issuer_path}`, `GET {p}/jwks`, `GET {p}/authorize`, `POST {p}/token`,
`POST {p}/register`, `GET|POST {p}/consent`. Bars: `None` on six (OAuth's own client auth, done by the
`oauth-as` library); `Admin` on consent. **There is no introspection (RFC 7662) and no revocation (RFC 7009)
route in legacy**, so a byte-identical rebuild adds neither; the RFC 8707 audience handling is
`allowed_resources`/`protected_resources` = busbar's own planes, `aud` = first protected resource.
The oracle's `auth.lifecycle` family is three SCRIPT cells (key-expiry/revoke/rotate) that never touch these
routes: byte identity of the rebuilt routes needs a judge recorded on the base binary (the earlier attempt's
29-cell shape, not its code), with `auth.lifecycle` run alongside to prove it is untouched.

## The state, and where each piece lives
| state | legacy home | rebuilt home |
|---|---|---|
| issuer, paths, ttl, key id, `default_grant` ceiling | `AsIdentity` in core config | contract data: the crate's own `Identity` derived from the `oauth_as:` section handed across the row |
| ES256 signing key | `RingEs256Key` (ring) | the crate's own signer; key material arrives resolved, as `Option<&str>`, never a `SecretRef` type |
| clients, codes, tokens, refresh tokens, grants | `oauth_as::store::MemoryStorage` in-process | the plugin's own store THROUGH THE STORE FACE: `busbar_contract::kinds::Store::{replay_put, replay_get, claim_key}` under a `control-oauth2` namespace; `claim_key` is the atomic take a refresh token needs |
| consent sessions + one-shot approval stake | `consent::Sessions` | same table, keyed in the store face; the operator subject stays `busbar-operator` |
| operator identity on consent | admin chain (`RouteAuth::Admin`) | the row declares the bar; the crate verifies nothing itself (governance face `VirtualKeyDirectory` is what the admin chain reaches, not the plugin) |

## Errors
Every refusal the crate itself makes (no pending request, no entropy, unrepresentable cookie, not-found,
boot refusals of the section) is a `PluginError { class, code }` with codes `oauth2.*`, catalog beside its
claims (`catalog.rs`, default locale `en`), classes from the closed ten. What `oauth-as` answers on the wire
is forwarded unchanged — the RFCs fix those bytes and the judge would catch a "better" one.

## The mount: a registry row, never a main.rs line
`crates/busbar/src/root/` gets ONE row: a `busbar_substrate::plane::registry::PlaneDecl` whose `build` lowers
the `oauth_as:` section into the crate's `Identity`, whose `routes(slot)` translates the crate's route table —
`claims.rs`, segments as `PathSeg::Lit` data so `kind-isolation:registry` can see them — into
`PlaneRouteSpec`s, and whose handler adapts a neutral `(method, path, headers, body)` into the crate's
`answer`. The root pushes `&DECL` in `register_planes()` exactly as the a2a/mcp/voice rows join; the
hard-wired `crate::oauth_as::routes::mount(router, oauth_as)` line in core's `router.rs` is the line the
delete removes. The crate names no transport, no axum, no substrate: `Cargo.toml` deps are `busbar-contract`,
`busbar-caps` and third-party (`oauth-as`, `ring`, `base64`, `serde`, `serde_json`).

## The ruling still owed before a line is written
`busbar × control` (the root's vocabulary cell) reads **1062** in this base's ledger (the coordinator's figure is
1063; the row's number on the landing base is the one that binds). A new control row in the root RAISES it;
the rebuild must drain that rise inside its own series (the legacy mount line, `App::oauth_as`, the config
lowering in core go out on the same commits the row comes in) or stop and report — it never declares a raise.
`Kind` in the contract has no `Control` variant: the crate implements `Plugin` with a kind the contract can
name, and `kind-isolation:faces` only refuses the plane/dialect/transport/unit entry faces, so that is legal
today and is recorded as the seam the control kind still owes.


## The name, measured twice

The instance was `oauth2`, and that was a wrong name: as a control-kind id it became a bare needle
that caught Microsoft's and Google's token URLs wherever core or the substrate mentioned them
(`busbar-core × control` 5200 → 5203, `busbar-substrate × control` 352 → 361). The ruling renamed it
to `issuer`. Measured on this tree, `issuer` is worse by that ruling's OWN criterion — a name that
collides with third-party wire vocabulary is a wrong name — and it collides with five kinds' RFC
vocabulary at once: RFC 8414 / OIDC in core (5200 → 5422), the X.509 certificate `issuer` field in
`busbar-transport-tls` (1 → 6, taking `kind-isolation:vocab` RED), the A2A card issuer
(`busbar-a2a` 172 → 434), the substrate's own `CardIssuer` face (352 → 419), `busbar-contract`
20 → 23 and the root 1062 → 1085. None of it is drainable: it is the tree's own wire vocabulary, not
a name of this crate. `tokenmint` has ZERO pre-existing hits in `crates/` and `xtask/` and is what
the crate's own description says it does. The branch is still `keep-control-issuer` — a branch name
is measured by nothing.

## What the cut-over actually is

* ONE row, `crates/busbar/src/root/control_tokenmint.rs`, pushed in `register_planes()` exactly as
  the a2a / mcp / voice rows join. It translates the crate's declared `claims::ROUTES` into
  `PlaneRouteSpec`s and maps the two declared bars in one `match` — `Bar::Open` → `RouteAuth::None`,
  `Bar::Operator` → `RouteAuth::Admin` — so the `CoreRouteTable` row each spec records is the row
  the deleted `oauth_as::routes::mount` recorded. The row lives in the COMPOSITION and not in the
  crate because a control crate's only busbar edge is `busbar-contract` and the row must name the
  substrate's registry.
* The CIMD fetch seam is filled by `root::control_tokenmint_fetch::GuardedFetch`, the legacy
  `GuardedFetch` moved verbatim — same policy, same ordering with the cloud-metadata arm first, same
  pinned client, same single deadline, same capped read, same refusal wording.
* `BuildCtx` gained two NAMELESS slots in its own `[SEAM]` commit (`resolved_section`,
  `resolved_secret`; ARCHITECTURE §1.1 amended). Nameless because `mcp_slot` and `agent_defs` are
  each spelled for the one row that reads them, which costs a field per row and puts a row's
  vocabulary in a seam every row reads. `resolved_secret` is an `Option<&str>` and never a resolver,
  so the crate that signs with the material cannot reach a second secret.

## The judge's finding, which is the reviewable part

The first judged run answered **401 on every cell**. `build` erases what it returns as
`Arc<dyn Any>`, so the slot's concrete type is `TokenMint` and never `Arc<TokenMint>` — and `routes`
asked for the latter, missed, and returned an EMPTY vec. Seven paths went unclaimed, the protocol
catch-all took them by construction, and a silent mis-mount is indistinguishable on the wire from a
deployment that is not an authorization server. The slot is now a `Slot(Arc<TokenMint>)` newtype and
the downcast is an `expect`: a failed downcast is the row disagreeing with itself and should end the
boot, not quietly unmount the surface.

## What remains owed, named rather than discovered

* **The state is still `MemoryStorage`, in-process.** Ruling (3) allows this and requires it be
  said: authorization codes, tokens, refresh tokens and registered clients are lost on restart. The
  seam is `oauth_as::store::Storage` — thirty async methods — over
  `busbar_contract::kinds::Store::{replay_put, replay_get, claim_key}`, and `claim_key` is
  load-bearing rather than decorative: the `take_*` methods must be an ATOMIC remove-and-return or
  refresh tokens double-spend across nodes. It was not lowered in the time this slot had.
* **The `oauth_as:` GRAMMAR stays in core** (`oauth_as::config`), and not out of inertia:
  `config_validate::secret_refs` walks `RootCfg` and must be able to SEE the `signing_key:`
  reference, because a secret the walker cannot reach is a secret nothing checks. Its move has a
  shape — `parse_section` + `config_validate` on the row, the crate's own `Section` as the parse
  target — and that is the next step. Until it lands, the row maps core's derived `AsIdentity` into
  the crate's `Identity` field for field, carrying every value and re-deriving none: a second
  derivation is a second chance to disagree about a path a client has already discovered.
