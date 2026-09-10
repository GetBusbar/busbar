# D36 — the dialect split

**Status:** the pattern, established by `busbar-plane-llm-openai`, the first crate of the dialect
kind, and COPIED once — by `busbar-plane-llm-responses`, whose landing is section 9. Written to be
copied: the next seven dialects should be a manifest, four files and a battery, with nothing decided
again. The second one was, and section 9 is what it cost.

---

## 1. What a dialect is, in one paragraph

A plane owns what a request MEANS — the IR, the step list, the operation classes, the meter
*classes*. A dialect owns how one vendor SPELLS it — which paths and headers name it, where the
model is, where the four metered quantities are reported, which credential its clients present and
which scheme its upstreams expect. The two change on different clocks, and that is the whole
argument for the kind: a vendor ships a seventh spelling, and a plane that carried a branch per
vendor is edited for it. A plane that carries none is not.

A dialect crate is therefore a **declaration** and a **delegation**, in that order of importance.
The declaration is constants. The delegation is four methods of four lines each, every one of them
calling the plane's own body with this crate's row as the argument. There is no second
implementation of the wire format in a dialect crate, and a dialect crate that grew one would be a
second copy of a vendor's protocol whose only provable property is that the two agree on whatever
cells someone thought to freeze.

## 2. The one edge

    dialect -> plane        (its own, exactly one)
    dialect -> contract     (the face every kind is written against)

and nothing else. Not a transport, not a unit, not a sibling dialect, not another plane, not the
codec, **and not a dev-dependency either**. That is the narrowest sink set in the plugin tree, and
it is what lets a plane stay dialect-neutral while its wire surface stays open.

The edge runs **dialect → plane**. The plane never names the dialect back;
`kind-isolation:deps` refuses the reverse, and the ledger's citation for the refusal is the same
clause that grants the forward direction. The plane holds a dialect's contribution as **data** — a
location row and a ladder — never as a value of the dialect's type, because holding the value would
be the plane naming the dialect.

A dev-dependency is a manifest edge like any other. The first dialect crate carried
`busbar-llm-codec` under `[dev-dependencies]`, copied from the plane's own test binary, and
`kind-isolation:test-deps` refused it. It was right to. A kind whose first crate reaches sideways in
its *test* manifest has established the coupling it was created to remove, in the one file every
later crate of the kind will be copied from. The battery asserts what the crate DECLARES, and a
declaration needs nothing registered to be read.

## 3. The skeleton

    crates/busbar-plane-<plane>-<dialect>/
      Cargo.toml                       two dependencies; NO [dev-dependencies]; no features
      src/lib.rs                       the type, holding its plane; `impl Plugin` (Kind::Dialect)
      src/meta.rs                      KEY, and the `DialectMeta` impl
      src/claims.rs                    the rungs, built with the PLANE's `claim()` builder
      src/dialect.rs                   LOCATIONS, ENTRY, and the four delegating methods
      tests/dialect_conformance.rs     the battery of section 6

The four-segment name is what resolves the crate to the dialect kind. `qa/construction.toml`'s
`[gate.plugin_kinds]` carries the pair

    plane   = ["crates/busbar-plane-*", "!crates/busbar-plane-*-*"]
    dialect = ["crates/busbar-plane-*-*"]

as **one** pair on purpose: narrowing the plane glob without adding the dialect glob leaves a
dialect crate of no kind at all, and leaving the plane glob open scores a dialect against the plane
rows — purity, neutrality, the plane skeleton — for a kind whose whole definition is that it carries
the vendor vocabulary a plane may not.

### `src/lib.rs`

The type CARRIES ITS PLANE, and that is the registration direction stated as a type:

```rust
pub struct OpenAi { plane: LlmPlane }

impl OpenAi {
    pub const fn new(plane: LlmPlane) -> Self { Self { plane } }
    pub const fn plane(&self) -> &LlmPlane { &self.plane }
}
```

Construction is the whole of registration on this side. There is no `install`, because a dialect
that could be pointed at a second plane after a boot proved the claim ladder disjoint would be a
dialect whose claims *in force* are not the claims that were *proved*.

### `src/claims.rs`

The rung numbers are the **plane's scale**, not the crate's. A rung is a statement about a CONTEST —
"these bytes are mine rather than that dialect's" — so its number only means anything against the
scale every other dialect is numbered on. A dialect being cut out of a plane declares the rungs its
rows already sat at; moving them would change which dialect answers a request two could read.

The claims are built with the plane's own `claim()` builder, which fills in the transport, the
credential scheme and the alternative set. Restating those in the dialect would be a second answer
to a question the plane already answers for all of its dialects, and the first request arriving on a
transport the plane did not think it claimed would be the one that noticed.

**Ascending rung order is required**, not tidy: the plane's merged walk takes the smallest unvisited
rung from each source and stops scanning a source the moment it can no longer win, which is sound
only for a source that is itself ordered.

### `src/dialect.rs`

`LOCATIONS` is a table of PLACES and nothing else. Nothing in a dialect crate parses or writes
anything.

`ENTRY` is the claim:

```rust
pub const ENTRY: DialectEntry = DialectEntry { locations: LOCATIONS, ladder: LADDER };
```

It is the only thing a boot needs from the crate, it is `const`-constructible, and it is DATA.

The four methods are the delegation, and each is one line:

```rust
fn decode_ingress<'u>(&self, frames: …, st: …, ctx: …) -> Result<Ingress<'u>, Decode> {
    self.plane().decode_ingress_as(&LOCATIONS, frames, st, ctx)
}
```

with `encode_egress_as`, `decode_response_as`, `encode_response_as` alongside.

## 4. The claim — how a dialect reaches a running node

A composition root seals `ENTRY` into the plane, and **the root names no dialect in its logic**:

- `crates/busbar/src/root/dialects.rs` is DATA and nothing else — one `const` per plane, one row per
  dialect crate. This is the only file in the root that names a dialect crate.
- `crates/busbar/src/root/registry.rs` iterates it. `llm_plane()` seals
  `DialectRegistry::sealed(dialects::LLM)`; `dialect_claims_of::<P>(entries)` is generic over the
  PLANE and blind to the dialect, reading `entry.ladder` (which every entry has) and `P::KEY` (which
  the plane has).

So a dialect crate is named in exactly two places: one line of `crates/busbar/Cargo.toml` and one
row of `dialects.rs`. **Adding the next dialect is a dependency and a row.**

**A plane's served surface is its own claims unioned with its registered dialects'.** A dialect's
claims are claims ON ITS PLANE — the rung scale is the plane's, the transport and scheme come from
the plane's builder, and the key a request is routed by is the plane's. A boot that unioned only the
plane's half seals a surface that answers on fewer paths than the binary can decode, and the request
arriving on the difference is refused as claimed by nothing while the crate that speaks it sits
registered in the same process. That is not hypothetical: it is exactly what the tree did between
the carve-out commit and the seam commit, and six pinned boot tests measured it as 43 claims where
48 were owed.

## 5. Cutting a dialect OUT of a plane

Two commits, in this order, and the second is what makes the first honest.

1. **The carve-out.** Move the rows and rungs from the plane into the new crate. The plane's own
   claim table loses them; the plane's ladder keeps their NUMBERS free. Prove byte-identity with a
   `golden_parity` suite against the pre-split output, and prove the plane no longer spells the
   vendor with a textual `neutrality` test over the plane's source.
2. **The seam.** Seal `ENTRY` in the root and union the claims. The claim counts, the sealed
   precedence order and the cross-plane overlap counts must come back to the SAME numbers, byte for
   byte. Anything else means the split changed which plane takes which bytes, which it must not.

## 6. The mandatory tests

Fifteen cases, and every one of them is about what the crate DECLARES, so none of them needs a
registry, a codec or a composition root.

**In the dialect crate** (`tests/dialect_conformance.rs`):

| # | case |
|---|---|
| 1 | `declares_the_dialect_kind_and_its_abi` |
| 2 | `implements_the_dialect_trait_object_safely` |
| 3 | `the_entry_is_a_constant` |
| 4 | `the_key_is_one_string_everywhere_it_appears` |
| 5 | `names_its_own_plane_and_no_other` |
| 6 | `the_dialect_holds_nothing_across_calls` (walk the type; no interior mutability) |
| 7 | `the_ladder_ascends` |
| 8 | `every_rung_names_this_dialect` |
| 9 | `the_ladder_and_the_claims_constant_agree` |
| 10 | `every_claim_carries_the_planes_transport_and_scheme` |
| 11 | `every_claimed_surface_has_a_verb` |
| 12 | `the_scheme_alternative_is_one_the_plane_declared` |
| 13 | `the_locators_and_the_row_name_the_same_places` |
| 14 | `one_meter_locator_per_class_the_plane_declares` |
| 15 | `the_response_ceiling_is_declared_in_precedence_order` |

**In the plane** — `neutrality.rs`: the plane's source names no dialect this crate now owns, as
TEXT, not as a type. **In the root** — a boot test that walks every registered entry's ladder,
asserts each rung's claim is in the sealed surface under the plane's key, names the rung NUMBERS
(a count is satisfied by any five claims), and asserts the merged ladder resolves those paths to the
name read OFF THE REGISTERED ROW rather than written in the test.

## 7. The checklist for the next dialect

1. `crates/busbar-plane-<plane>-<dialect>/` on the skeleton of section 3. Two dependencies. No
   dev-dependencies. No features — a dialect compiled two ways is two dialects, and the registry
   that sealed one of them could not say which.
2. Rungs at the numbers they already occupy in the plane's ladder.
3. The battery of section 6, all fifteen.
4. Carve-out + seam as two commits (section 5), with `golden_parity` byte-identical.
5. One line in `crates/busbar/Cargo.toml`; one row in `crates/busbar/src/root/dialects.rs`. Nothing
   else in the root.
6. Ledger: `[[dep]]` rows for `dialect -> contract` and `dialect -> plane` at `count = "1"`,
   `verdict = "allowed"`, and one for `root -> dialect`. All three classes are already in
   `ARCHITECTURE_ALLOWED`, so the second dialect adds rows and no rule.
7. `cargo xtask gate kind-isolation` and its ship twin.

**The eight that follow, and what each costs.** `responses` — LANDED; see section 9 — (rung 10;
`/input`, `/max_output_tokens`, four different meter pointers — the reason it is a SECOND crate and
not a branch in the first). `anthropic` (header-detected: `anthropic-version`, `anthropic-beta`,
`x-api-key`). `gemini` (`:generateContent` and its four siblings, plus the `/v1beta/models` tail —
the loosest path family of the six). `bedrock` (`HeaderPrefix("authorization",
"AWS4-HMAC-SHA256")` and `/converse`; the only one whose credential scheme is not bearer-shaped).
`cohere` (`/v2/chat`, `/v2/embed`, `/v2/rerank`). Then the three that are NOT LLM-plane dialects and
must not be filed as if they were: `mcp` and `a2a` are dialects of their own planes, and `voice` is
a dialect of the duplex plane whose claims sit on `ws` — each takes this pattern against a different
plane, and none of them may take a shortcut through `busbar-plane-llm`.

## 8. The open decision this landing surfaced

`kind-isolation:matrix` scores a kind's vocabulary as its MEMBER PACKAGE NAMES and their ids. Until
the first dialect crate existed the dialect kind had no members, so the whole column measured zero —
and the `openai` vocabulary that has been in `busbar-core` (579 hits), `busbar` (408),
`busbar-llm` (216) and twenty-two other crates all along was invisible. The first crate of the kind
is what made it visible. **That is the gate working**, and the column is a true statement about
coupling the tree already had.

It cannot be written down, and that is also the gate working. `minted_rows` refuses any `[[cell]]`
or `[[edge]]` the merge base does not carry, because a new row is a `0 -> N` raise wearing the
clothes of a first measurement — the one raise `ceiling-rose` cannot see, and the gap a red team
walked straight through. There is no declaration table for a minted row, by design.

So there are exactly two ways out, and both are owner decisions rather than landings:

- **Drain it.** The R7 renames delete the vendor vocabulary from the legacy crates, and the column
  goes to zero the way every other ledger row is meant to. This is the intended path and the ship
  twin already demands it — the twin owes the matrix at ZERO everywhere.
- **Declare the mint.** Give minting the same declared-transaction mechanism
  `[gate.ceiling_raises]` gives a raise: a table naming the exact row, the measured N, a reason long
  enough to be one, and self-expiry once the base carries the row. This is the mechanism the rest of
  the ceiling machinery already has, and its absence here is why the first crate of ANY new kind
  cannot land green — which will be true again for `control`, and for every kind after it.

Until one of the two lands, `kind-isolation:matrix` is a standing red for the dialect column, and it
should be read as the size of the drain rather than as a defect in this landing.

---

## 9. The checklist, ticked for `responses`

`busbar-plane-llm-responses` is the second crate of the kind and the first COPY of this pattern.
The checklist of section 7, item by item, with what each cost:

1. **The skeleton.** ✅ `crates/busbar-plane-llm-responses/`, the five files of section 3 plus the
   battery. Two dependencies (`busbar-contract`, `busbar-plane-llm`), no `[dev-dependencies]` table
   at all, no features. Nothing was decided again; what was chosen is the values a dialect exists to
   declare.
2. **Rungs at the numbers they already occupy.** ✅ Rung 10, `PathSuffix("/v1/responses")`, built
   with the plane's own `claim()` builder.
3. **The battery of section 6, all fifteen.** ✅ Fifteen of fifteen, red first: the file went in
   against a crate with no `dialect` module and no type, and rustc refused both imports. Only two
   cases needed a sentence about the vendor — the cache-WRITE locator (a pointer here where the
   sibling declares the empty "not reported" string) and the response ceiling (ONE member name here
   where the sibling declares two). Those two differences are why this is a second crate, so those
   are the two cases that carry a reason.
4. **Carve-out + seam as two commits, `golden_parity` byte-identical.** ✅ Eighteen frozen cells:
   `req_g2r_{plain,tools,inline_data}`, `req_o2r_{plain,tools,attachments}`,
   `req_r2a_{plain,tools,input_file}`, `resp_a2r_{plain,tool_use,thinking}`,
   `resp_r2g_{plain,reasoning,function_call}`, `resp_r2o_{plain,reasoning,function_call}`. Proved red
   by taking the harness fixture back out with the plane's row already gone: both parity cases and
   three ladder cases panicked. The legacy Responses path in `busbar-llm-codec` is untouched and
   stays until R5 deletes it — the claim this landing makes is EQUALITY with it over the corpus, not
   its removal.
5. **One line of `crates/busbar/Cargo.toml`; one row of `dialects.rs`.** ✅ Exactly that, and not one
   line of `registry.rs`. The six pinned boot numbers were red first at one below their pins (llm 24
   of 25, 47 sealed of 48, 62 path-family of 63, 22 of 23, 152 of 153, and the sealed-order row with
   `llm PathSuffix("/v1/responses")` absent) and all six answer again in the same byte-for-byte
   order.
6. **Ledger.** ✅ Three `[[dep]]` rows at `count = "1"`, `verdict = "allowed"` — `busbar ->
   busbar-plane-llm-responses`, and the dialect's two sinks. **No rule and no table in
   `xtask/src/gates/kind_isolation.rs` changed**, which is item 6's own prediction coming true: all
   three classes were already in `ARCHITECTURE_ALLOWED`. No `[[registered]]` row: the four-segment
   glob names the kind, and a per-crate row would be a second place kind membership is stated.
7. **The gate and its ship twin.** ✅ 10 of 11 rows PASS. `:matrix` is the standing red of
   section 8 — this crate mints exactly one cell, `busbar-plane-llm-responses × dialect = 1`, its own
   package name becoming visible to the census, and the twin shows it in that one cell and no other.

**One boot test was wrong in a way only a second dialect could reveal**, and that is the most
useful thing this landing found. `the_merged_ladder_answers_for_the_registered_dialect` read
`dialects::LLM[0]` — a test about the FIRST entry wearing the name of a test about registration. It
would have gone on passing while a second registered row answered for nobody. It walks every entry
now, feeds the plane each path rung's own selector text and compares against the name read off the
row that declared it. **Every later dialect should expect to find one of these**: the first crate of
a kind cannot tell a loop over a table from a lookup of its only element, and the second crate is
the first thing that can.

**What the third crate — `anthropic` — needs, beyond a copy of this one.**

- **Header rungs, which neither of the first two has.** Rungs 2 (`anthropic-version`,
  `anthropic-beta`), 4 (`x-api-key`) and 11 (`PathContains("/v1/messages")`) — three rungs at three
  numbers, two of them header forms. Two consequences. The battery's `every_claimed_surface_has_a_verb`
  compares verbs against DISTINCT RUNGS, so three rungs want at least three verbs. And the boot test
  generalised above skips non-path selectors by design: `anthropic` is the first dialect that will
  need the header arm, and the `_ => continue` in that match is where it says so rather than being
  silently skipped — filling it in is part of that landing, not an afterthought.
- **A `SCHEME_ALT` that is not `bearer`.** Its clients present `api-key`, which the plane declares,
  so `the_scheme_alternative_is_one_the_plane_declared` is the case that will earn its keep for the
  first time.
- **All four meter classes reported, at `/usage/{input,output}_tokens` and the two
  `cache_{read,creation}_input_tokens` members** — the same SHAPE as `responses` and different
  spellings, which is precisely the case the positional locator count exists for.
- **A ceiling with one spelling (`/max_tokens`) that this dialect REQUIRES.** `requires_max_response`
  reads the legacy codec's `DECLS` by name and this is the dialect it answers `true` for, so the
  carve-out has to leave that answer unchanged while the plane stops naming the key — the one place
  where the third carve-out is harder than the second rather than identical to it.
- **Golden cells in both directions with almost every other dialect**, which makes it the widest
  parity surface of the six; budget the carve-out commit accordingly.
