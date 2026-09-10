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

## The drain, and the four lines that would not drain

`busbar x control` -- the composition root's naming of this kind -- landed at **1138** against a base
of **1062** (1063 at the merge-base; this branch had already drained one). The owner's ruling is
that a control-word rise in the root is a CONVENIENCE and is drained, never declared. It was drained
to **1071**, and what remains is four lines:

| line | hits | why it is not a convenience |
|---|---|---|
| `crates/busbar/Cargo.toml`, the ONE dependency line | 6 | the `[[dep]]` admission itself. The dependency is RENAMED there (`oauth-issuer = { package = "busbar-control-tokenmint", path = "..." }`) so the package is spelled where the edge is declared and NOWHERE else in `crates/busbar` -- not in an identifier, not in a comment, not in a filename. `kind-isolation:deps` resolves `package = "..."` renames, so the edge is still measured under the real package name: the drain takes the vocabulary out of the composition's source, it does not take the edge out of the graph. Six because the line names the package twice, as the `package` and as the `path`. |
| `admin_noun:` | 1 | a `PlaneDecl` field name every row in the registry fills |
| `admin_routes:` | 1 | likewise |
| `const OPERATOR_BAR: RouteAuth = RouteAuth::Admin;` | 1 | the seam's own enum variant for the operator chain, bound to a name once so the `match` spells it no second time |

The ruling's own escape is "the count is the base's + exactly that one line, stated". Six of the nine
are that one line. The other three are the SEAM's spelling rather than this landing's, and they fall
with R7 -- when the sibling control surface becomes `busbar-control-admin`, the bare id `admin` stops
being that surface's needle and all three stop scoring. **They are declared, not hidden**:
`qa/construction.toml` carries the raise with the four lines enumerated, and this section is the
statement the ruling asked for.

How the other 67 went:

* **The filenames.** The matrix scans a file's own PATH before it reads a byte of it, so
  `control_tokenmint.rs` was a hit per needle before its contents were counted. The two root files
  are `root/oauth_issuer.rs` and `root/oauth_issuer_fetch.rs`.
* **The identifiers.** Every `busbar_control_tokenmint::` path is now `oauth_issuer::`, the
  manifest's rename.
* **The prose.** Every doc comment that named the crate, the kind, or a sibling row by instance now
  says what it means without the instance.
* **The two scanners, reconciled by a spelling and not by a row.** `busbar x control` read 1132 by
  segments and 1138 by windows, and the whole of the disagreement was the camel type name
  `TokenMint`: the segment scanner splits it to `token` + `mint` and misses the needle, the window
  scanner reads it whole and does not. The ledger's route through that is a `[[disagreement]]` row,
  which on this branch would be MINTED. So the TYPE was renamed -- `TokenIssuer` -- and the cell
  needs no row at all. That is the general rule this landing followed: a scanner disagreement is a
  spelling problem before it is a ledger problem.
* **The other cells fell with the same edit**: `busbar x plane` 1811 -> 1799, `x legacy` 102 -> 97,
  `x transport` 956 -> 955, `x substrate` 11 -> 10. Each is declared with the face that measured it.
* **The substrate's `BuildCtx` seam prose** named two sibling rows and a reference type to explain
  two NAMELESS slots -- the vocabulary the seam exists not to carry. `busbar-substrate x plane`
  770 -> 768 and `x secret` 36 -> 35, both back to base.

### The issuer crate stopped naming four other kinds

`caps` 1 -> 0 (a manifest sentence that named the capability crate to say it is *not* a dependency),
`store` 6 -> 0 (every hit was the path `oauth_as::store::Memory...`, now one `use oauth_as::store as
backing;` per file), `secret` 1 -> 0, `legacy` 2 -> 0, `control` 15 -> 0 (prose about the node's
operator chain; one private constant `ADMIN_SUBJECT` -> `OPERATOR_SUBJECT`, **value unchanged**; and
a dynamic-registration fixture whose privileged scope was literally spelled `admin`, now `elevated`,
which is arbitrary to what that test proves). Six `[[cell]]` rows and three `[[edge]]` rows were
struck as dead allowances.

### What is still RED, and the blocker

Two MINTED `[[cell]]` rows: `busbar-control-tokenmint x transport` (44) and `x plane` (27).

* **transport is not drainable.** This is an HTTP authorization server; `http::Request` is its own
  vocabulary, and `http` is the instance id of `busbar-transport-http`. The 44 hits are the `http`
  crate dependency and its types.
* **plane is drainable and was not drained in this slot's time**: 27 hits, almost all RFC 8707
  protected-resource fixtures (`mcp:read`, an MCP endpoint URI) in the crate's own tests, plus the
  prose around them. Renaming the fixtures drains it; the crate's tests must be re-run behind it.

`kind-isolation:matrix` refuses a minted row unconditionally. Its own refusal text names a second
route -- *"land the row in a commit whose message says why the tree now needs it"* -- **and that
route is not implemented**: there is no `[[minted]]` table and no reader for one in
`xtask/src/gates/kind_isolation/matrix.rs`. Landing a crate that did not exist at the merge-base and
that must name the `http` crate is therefore not expressible in the gate today. That is the blocker,
and it is a gate change rather than a code change: either the commit-message admission the refusal
already promises, or a `[[minted]]` table read on the same hand-reader terms as `[[edge]]` (cite,
why, drain) with the row's own irreducibility as the cite.

## Still owed after this slot, in the order they should be taken

1. **The `oauth_as:` GRAMMAR is still core's.** `busbar-core/src/oauth_as/` is down to `config.rs`
   (283 lines) and `mod.rs`, and the reason it is still there is unchanged and still good:
   `config_validate::secret_refs` walks `RootCfg` and must be able to SEE the `signing_key:`
   reference, because a secret the walker cannot reach is a secret nothing checks. The move's shape
   is `parse_section` + `config_validate` on the ROW, with the crate's own `Section` (which already
   exists, `oauth_issuer::config::Section`) as the parse target; `RootCfg::oauth_as`,
   `config::prepass`'s `LiftedValue::OauthAs` and `secret_refs`'s `AsIdentity` destructure all move
   with it, and the config-schema snapshot must come out byte-equal or additive. It was NOT
   attempted in this slot: a half-moved grammar is a boot that validates one thing and serves
   another, and the byte-identity judge covers the ROUTES rather than the parse.
2. **The state is still the protocol library's in-process backing.** Ruling (3) allows this and
   requires it be said: authorization codes, tokens, refresh tokens and registered clients are lost
   on restart. The seam is the library's `Storage` trait -- thirty async methods -- over the
   contract's durable face. `crates/busbar-contract/src/store.rs` **is not on this base** (it is on
   `origin/keep-api-kinds-to-contract`), so the transitional shape stands: the state stays behind
   the plugin's own surface, named nowhere outside it, and this note carries the row. The
   load-bearing method is **`claim_key`**, and it is load-bearing rather than decorative: every
   `take_*` on that trait must be an ATOMIC remove-and-return, or a refresh token is redeemed twice
   across two nodes and the second redemption mints a second access token from a grant that was
   already spent. A non-atomic `replay_get` + `replay_put` pair does not close it.
3. **`Kind` in the contract still has no `Control` variant.** The crate implements `Plugin` with a
   kind the contract can name, and `kind-isolation:faces` only refuses the plane/dialect/transport/
   unit entry faces, so that is legal today and is recorded here as the seam the control kind owes.

## The re-pick onto the instruments tip, and the one thing that is still owed to the door

**Status: RE-PICKED AND LEDGERED.** The whole series was re-picked onto
`origin/keep-gate-instruments-on-tip` @ `50b5da4b2` — the tip that carries the `[[minted]]`,
`[[renamed]]` and `[[gate.census_retired]]` doors — with E1's re-keyed plugin-error series and G1'
beneath it. The judge is byte-identical on the new base: 29 cells, 0 diverging, at every prefix.

### The crate mints ONE cell, and seven drained

The previous slot ended with two minted `[[cell]]` rows and no door to put them through. There is a
door now, and only one row goes through it.

* **`x plane` was 27 and is ZERO.** Every hit was the bare instance id of a sibling data plane in
  text that did not need it: the RFC 8707 protected-resource fixtures in the crate's own tests
  (`mcp:read`, `mcp:write`, a `https://gw.example.com/mcp` audience) and doc comments that cited a
  sibling row's constants and its protocol revision by name to explain this crate's own. The
  fixtures are arbitrary to what those tests prove — they prove that a self-registered client
  cannot ask for more than the operator's `default_grant`, and the scope's spelling is not the
  subject — so they now read plane-neutral literals. All 28 of the crate's tests pass behind the
  rename. This is the same move the landing already made for `admin` -> `elevated`.
* **`x dialect` was 1 and is ZERO**: the word `responses` in a sentence about what the RFCs fix. It
  is an LLM dialect's instance id, and the sentence did not need it.
* **`x transport = 44 STAYS.** This is an HTTP authorization server. `http::Request` and
  `http::Response` are its own vocabulary and the wire its RFCs are written against, and `http` is
  the instance id of `busbar-transport-http`. Three hits are the manifest dependency and forty-one
  are the types at the crate's own surface, already hoisted to one import per file. A control crate
  that answers an HTTP request cannot stop naming HTTP. The drain is the day the neutral route seam
  carries its own request type.

`moved_from` is deliberately absent: the served half of `busbar-core/src/oauth_as/` was DELETED and
the surface REBUILT against a protocol library, so this is not a carve-out. Claiming
`moved_from = "busbar-core"` would put busbar-core's own `x transport` ceiling (2081) over a 44-hit
row, which is a ceiling that measures nothing.

### The ruled 1071 is 1080 on this base, and the difference is the INSTRUMENT

The owner ruling accepted `busbar x control` at **1071**. On this base it measures **1080**, and the
nine are not a coupling this landing grew. T0-A widened the matrix scan set from `crates/**/*.rs` +
`crates/**/*.toml` to EVERY readable non-binary file — a red team had gone around the old set with a
`.yaml` twin, a `.inc` and a `.txt` — so the byte-identity judge's OWN recording,
`crates/busbar/tests/oauth_issuer_golden/{config.yaml,routes.txt}`, is scored now and was not scored
on the base the ruling was made against.

MEASURED BOTH WAYS, which is the only way to say this honestly. Move that one directory aside and
this tree reads the ruled figures EXACTLY:

| cell | merge-base | ruled / without the recording | with it |
|---|---|---|---|
| `busbar x control` | 1063 | 1071 | **1080** |
| `busbar x plane` | 1798 | 1799 | **1802** |
| `busbar x transport` | 939 | 955 | **970** |
| `busbar x auth` | 25 | 25 | **26** |

The 28 hits are not drainable, and the reason is the point of the file they are in. `routes.txt` is
the wire, pinned cell for cell — four of its hits are the two `missing or invalid admin credential
(Bearer or x-admin-token)` bodies, and fifteen of the transport hits are the `http://127.0.0.1:<port>`
endpoint URLs the metadata document lists and the recorded `content-type` headers. `config.yaml` is
the boot the recording was taken against: the consent route's bar is `Admin`, so the node must run
an operator listener and an auth chain for four of the twenty-nine cells to exist at all. Changing
either changes what the judge compares, which is the one thing this landing may not do.

Each is declared in `qa/construction.toml` with the split stated line by line, and the ruling is
asked again against the wider scanner: **`busbar x control` at 1080, of which 1071 is the ruled
figure and 9 is the judge's own recording becoming visible.**

### THE ONE THING STILL OWED, AND IT IS A ONE-LINE ACTION ON THE INTEGRATION LINE

`kind-isolation:matrix` is down to TWO findings, and they are one cause:

```
minted-row        [[cell]] busbar-control-tokenmint × transport
unannounced-mint  [[minted]] busbar-control-tokenmint
```

`[[minted]]` requires that `crate` be named by an `[[announced]]` row **in the merge-base's copy of
the ledger**, and the merge-base (`4197eb09`) announces this crate under the name it had when it was
announced — `busbar-control-oauth2`. The C1'' ruling renamed the instance to
`busbar-control-tokenmint` for reasons that are measured and stand. So the base announces this
crate, under a name the mint rule cannot see.

A `[[renamed]]` row is written and does not close it: `[[renamed]]`'s stated contract is "every rule
that asks the base about `to` asks it about `from` instead", and it delivers that for `[[cell]]`,
`[[edge]]` and `[[disagreement]]` row keys and for dependency edges — but the `[[announced]]` lookup
in `minted_rows` reads `m.krate` raw
(`xtask/src/gates/kind_isolation/matrix.rs`, `if !at_base.announced.contains_key(&m.krate)`).

**There are two ways through, and the first is the right one.** The refusal names it itself: *"land
the `[[announced]]` row first, on the integration line, and mint against it afterwards."* The
integration line carries an `[[announced]]` row for this crate already; it needs the four-word
rename `busbar-control-oauth2` -> `busbar-control-tokenmint` applied to it, and this branch's mint is
admitted with no gate change at all. The second is to route that one lookup through
`reg.base_names()` like every other history question in the module — defensible, in the spirit of
the `[[renamed]]` doc, and admitting nothing that was not already announced — but it is a change to
a ratchet and belongs in its own commit with a red-before-green case, not smuggled in beside a
landing. **A ratchet is not weakened on the branch it happens to inconvenience.**

### Still owed, unchanged

The three items in the section above stand exactly as written: the `oauth_as:` grammar is still
core's, the state is still the protocol library's in-process backing, and `Kind` still has no
`Control` variant.
