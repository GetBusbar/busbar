# S19-orphaned-rows

Eight verified findings with no id block to live in.

A second agent swept `P04-prior` independently and converged on the same three withdrawals the
committed pass had already made — good evidence those withdrawals are right. But by the time it
finished, `X-3300..X-3399` was fully consumed by the committed pass, so every row it held would
have collided on an id already naming a different finding. **It wrote nothing and reported
instead**, which is the correct call and the reason these are recoverable at all.

**This file carries ROWS ONLY — no verdict lines.** Every file named below already holds a verdict
from its own slice. Adding verdict rows here would claim those files twice and turn
`sweep-coverage:disjoint` red over a bookkeeping artefact.

## ROWS RAISED

### X-4100 · two unauthenticated discovery documents share an op class with the authenticated one
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-plane-a2a/src/plane.rs` — `surface_of` maps both unauthenticated discovery
           documents to `OP_AGENT_CARD` (`:350-352`, `:413`), the same op class as the
           authenticated extended card (`:357`). `authenticate` treats only `OP_PUSH_EVENT` as open
           (`:755`), so a surface whose claims are declared `open_http` (no scheme) is narrowed to
           `bearer`. Prior row B50 saw the symptom; the op-class collision is the mechanism, and it
           changes what the fix has to be.
ACTION:    Give the unauthenticated discovery documents their own op class rather than widening
           `authenticate`'s open set, so the open surface is declared rather than excepted.

### X-4101 · the egress trust seam is never fed, so pinning is unreachable in every shipped build
CLASS:     auth
CERTAINTY: VERIFIED
EVIDENCE:  Re-derived here, not relayed. `git grep -n build_egress_client_with_trust -- 'crates/**/*.rs'`
           excluding tests returns one production call site: `crates/busbar-transport-http/src/lib.rs:333`,
           `build_egress_client_with_trust(settings, &EgressTrust::default())`. Control: the only
           non-default `EgressTrust { … }` construction in the tree is
           `busbar-contract/src/transport/tests/redaction_tests.rs:27`. SPKI pinning, extra trust
           anchors and client certificates are therefore unreachable in every shipped build.
ACTION:    Carry the operator's configured trust into the call at `:333`, or state in the contract
           that the seam is dormant and why.

### X-4102 · a legal colon-less SSE field is dropped as a comment, and the oracle shares the bug
CLASS:     customer-surface
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-transport-sse/src/proto.rs` — `SSE_FIELDS` are colon-bearing needles matched
           with `starts_with` (`:110`, `:128`). A legal field line with no colon (`data\n\n`) does
           not match and is treated as a comment. The test oracle carries the same assumption, so
           the two agree while both are wrong — the shape a second reader cannot catch.
ACTION:    Match the field name up to an optional colon, and give the oracle an independent
           expectation rather than the parser's own rule.

### X-4103 · one transport can interrupt a blocked write; three cannot
CLASS:     missing-code
CERTAINTY: VERIFIED
EVIDENCE:  `raced_write` exists only in `crates/busbar-transport-tcp`. `tls`, `ws` and `stdio` have
           no equivalent, so a write blocked on a peer that has stopped reading cannot be
           interrupted — which is precisely the failure tcp's own doc says must not happen.
ACTION:    Hoist the raced-write shape to the shared transport layer so every transport inherits it.

### X-4104 · the refusal path is the one write path with no delimiter guard, and every test misses it
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-transport-stdio/src/transport.rs` — `write` (`:406`) and `encode_envelope`
           (`:446`) both guard the frame delimiter; `write_refusal_line` (`:540-551`) does not. All
           three refusal tests pass a delimiter-free body, so no case can distinguish a guarded
           refusal from an unguarded one.
ACTION:    Guard the delimiter in `write_refusal_line` and give one refusal test a body containing
           the delimiter.

### X-4105 · a registration check documented as running at registration has zero callers
CLASS:     instrument-blind
CERTAINTY: VERIFIED
EVIDENCE:  Re-derived here. `registry::facts::undeclared` is defined at
           `crates/busbar-contract/src/transport/registry.rs:61` and appears in production nowhere
           else — the only other mention is a doc comment at `transport/dest.rs:226`. Control: its
           sibling `is_reserved` is defined at `:51` and CALLED at `:65`. Seven `TRANSPORT_FACTS`
           declarations feed a check nothing runs.
ACTION:    Call it at registration as its doc says, or delete it and the declarations it was to
           police.

### X-4106 · two decoders of one on-disk format, and the hardening landed on the dead one
CLASS:     abi
CERTAINTY: ADJUDICATE
EVIDENCE:  `crates/busbar-mcp/src/record.rs` and `crates/busbar-kernel/src/calllog.rs` decode the
           same on-disk format. The `checked_add` overflow hardening was applied to one copy; the
           unchecked copy is the one a future admin read verb reaches. Latent today because that
           verb does not exist yet — which is why this is ADJUDICATE and not VERIFIED.
ACTION:    Collapse to one decoder before the read verb lands, so the hardening cannot be bypassed
           by reaching the other copy.

### X-4107 · the bare-CR bug is on the live SSE path, not only the dead one
CLASS:     drift
CERTAINTY: VERIFIED
EVIDENCE:  `crates/busbar-mcp/src/mcp/client/transport.rs` — ENG1 records the bare-CR handling bug
           against the dead `progress_frames`. It also sits on the live `last_sse_data` path
           (`:454`, called at `:196`). Fixing only the site ENG1 names leaves the reachable one.
ACTION:    Fix `:454` and re-point ENG1 at the live site.

## ALSO WORTH A RULING, NOT RAISED AS A ROW

`crates/busbar-plane-a2a/src/frame.rs` — the entire operator-rewrite seat (`rewrite`, `Frame`,
`Transform`, `Tap`, `Direction`) has exactly one consumer tree-wide: its own integration test. Its
doc says "the plane crate applies these seats to real bytes." The committed P04 pass names only the
two traits, not the seat as a whole.

## THE SYSTEMIC LESSON

Three rows in the committed pass were withdrawn because the prior ledger recommended porting code
that already exists. **"Ledger row OPEN" is not a measurement.** Two independent sweeps reached that
conclusion separately, which is the strongest form this evidence comes in.
