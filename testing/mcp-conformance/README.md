# Independent MCP conformance battery

A differential conformance harness for **any** MCP server and client, written
from the published Model Context Protocol specification, revision
**2026-07-28**.

It contains no knowledge of any particular implementation. A target is a launch
command. There are no `if (subject === X)` branches, and adding one would be a
defect.

Every test cites the specification clause it asserts on. `node bin/mcp-battery.mjs list`
prints every test, its tier, and the defect it catches.

## Why this lives here

It used to live in a private repository, and it was moved here deliberately.
That repository is on an internal Gitea host with
**no route from a GitHub-hosted runner**: reaching it needed a repository
**secret** *and* a reachable private host, and the moment a control leg depends
on either, "the control legs run ALWAYS" becomes aspirational rather than true.
`.github/workflows/mcp-conformance.yml` now contains **no secret at all**, and
that is the property the move bought. The sibling A2A batteries were moved into
`testing/` first, for exactly this reason.

Nothing was lost by making it readable: this harness contains no product
knowledge by construction — that is the first paragraph above, and
`scripts/negative-control.sh` is what keeps it honest. Any other copy is
historical; **this** copy is authoritative.

## Skips are not passes

A skip is the honest report when the harness is being exercised for its own
sake. It is the wrong report when the run is a **release gate**, because a skip
renders as a green tick over a surface nobody touched. Set `MCP_NO_SKIPS=1` and
every `ctx.skip()` becomes a **FAILURE** naming what was not tested and why.
`scripts/mcp-conformance.sh --battery-subject` sets it; the control and
negative-control legs do not.

Concretely, today: the six `pr`-tier **SEAM** tests need busbar's MCP *client*
direction (to mount the battery's fake server as an upstream). That direction
does not exist yet, so under the gate those six are **RED** — which is correct,
because the seam is precisely the property that is meaningless with only one
direction built.

## Quick start

```bash
./scripts/setup-control.sh      # install the pinned control (python mcp==2.0.0)
./scripts/run-control.sh push   # 15 tests, ~16s. Must be green.
./scripts/negative-control.sh   # prove the battery catches broken peers
node bin/mcp-battery.mjs list   # every test, its tier, and the defect it catches
```

## Point it at something

```bash
node bin/mcp-battery.mjs run \
  --name "my-implementation" \
  --server-cmd "/path/to/thing serve --stdio" \
  --client-cmd "/path/to/thing connect" \
  --tier push,pr --out reports/subject.json

node bin/mcp-battery.mjs compare \
  --control reports/control-push-pr.json \
  --subject reports/subject.json
```

Or `MCP_SUBJECT_SERVER_CMD=... ./scripts/run-subject.sh` to do both and diff.

## Layout

```
bin/mcp-battery.mjs      CLI: run | compare | list
src/core/spec.mjs        98 spec clauses, each a verbatim quote + URL + RFC2119 level
src/core/runner.mjs      test registry; the assert/variance/recommend distinction
src/core/stdio-peer.mjs  byte-level stdio driver (sends things no SDK would send)
src/core/differential.mjs  control-vs-subject comparison and report rendering
src/core/target.mjs      the target abstraction: a launch command, nothing more
src/suites/              server-conformance, server-adversarial, server-concurrency,
                         client-role, seam
fakepeer/fake-server.mjs a deliberately misbehaving MCP server, 24 named modes
control/                 the pinned reference server, client, and known-deviation baseline
scripts/                 setup-control, run-control, run-subject, negative-control
```

## The one design rule

```js
ctx.assert(clauseId, cond, detail)  // spec MUST. Fails. Must cite a real clause.
ctx.variance(key, value)            // spec permits variation. NEVER fails. Diffed.
ctx.recommend(key, ok, text)        // our opinion. Never fails. Advisory.
```

`ctx.assert` rejects any clause id not present in `src/core/spec.mjs`, so a
requirement cannot be asserted without citing it. Everything the spec leaves
open is recorded and diffed instead, because a differential harness that fails
on every legal difference gets switched off within a week.

## Control pin

`control/requirements.txt` pins `mcp==2.0.0` exactly, and CI re-checks it. A
control upgrade changes what "conformant" means for the whole battery, so it
must be a deliberate, reviewed commit with the new green output recorded in the
commit message.

`control/control-baseline.json` lists known deviations of the control from the
spec, each with the verbatim clause, the observed behaviour, our judgement and
the counter-argument. It is not a way to silence inconvenient tests: if a
deviation stops failing, the run reports **UNEXPECTED PASS** and the entry must
be deleted.
