# control-oauth2 rebuild — core's `oauth_as` as a CONTROL-kind plugin (design, C1)

**Status: design only; paused by the coordinator 2026-09-09 (resume note in the last commit).** Base
`origin/keep-plugin-error-seam` @ 9aca51390 + governance-face commits 682216299 8b754136e 5bedb49e6, cherry-picked.

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
