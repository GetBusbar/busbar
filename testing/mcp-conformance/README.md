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

## How busbar itself is armed, and why it is not a variable

For the whole of 1.5.5 the release gate's subject leg reported `NOT ARMED, SO
NOT RUN` — correctly, and every day. It wanted `MCP_SUBJECT_SERVER_CMD`, a
repository variable naming *a command that starts an MCP server on stdio*, and
no such command exists: **busbar has no stdio MCP surface.** Its MCP plane is an
HTTP OAuth resource server, deliberately. A variable nobody can fill in from a
GitHub-hosted runner is not an arm.

So the leg is armed the way the official-suite leg is — from the **binary built
in the job**, never from `vars.*`. `scripts/mcp-conformance.sh --battery-subject`
boots that binary on loopback via `scripts/mcp-subject/boot.sh` (same real
audience-bound credential, same proof that the plane boundary is intact before
any verdict is believed) and points this battery at it through the transport
adapter:

```
scripts/stdio-http-bridge.mjs <url>    stdio frames in, Streamable HTTP out
```

The adapter's header states what it does and does not do. In short: bodies are
forwarded **byte for byte** and never repaired, results are never synthesised,
and the mirrored `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` headers are
*derived from the body* — so a body that omits one still reaches busbar's own
answer for that omission rather than being converted into a header defect.

One honest consequence, stated rather than filtered: on this leg the `STDIO.*`
clauses judge the **adapter**, because busbar has no stdio surface for them to
judge. They stay in the run — a filter is a knob, and the moment there is a knob
the number is negotiable — and are read as adapter checks. Everything else
(error codes, catalogue shape, survival under hostile input, concurrency,
statelessness) is busbar.

The two arming variables still work and still take precedence, for anyone
pointing this battery at something that is not this build. Nothing in CI depends
on one being set.

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
scripts/                 setup-control, run-control, run-subject, negative-control,
                         stdio-http-bridge (the transport adapter that arms an
                         HTTP-only subject)
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
