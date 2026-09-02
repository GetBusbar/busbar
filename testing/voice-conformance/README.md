# Voice (4th-plane) conformance battery — SCAFFOLD

A conformance battery for busbar's **voice** plane, at structural parity with the
sibling MCP (`testing/mcp-conformance/`) and A2A (`testing/a2a-*`) batteries.

**This is a scaffold.** The voice runtime does not exist yet, so no leg asserts
real conformance today. What lives here is the **shape** — the runner, the leg
scaffolds, the verdict emitter, the CI workflow — landed **green** in an honest
"scaffolded, legs pending" state, so that:

1. the shape is enforced (and its accounting proven) *before* the first real leg
   depends on it, and
2. filling a leg later is a **drop-in**, not a rebuild.

## Why a scaffold is a legitimate green here

The MCP and A2A batteries make `NOT ARMED, SO NOT RUN` a **RED** state, because
for those planes the runtime exists and a disarmed subject leg renders as the
identical green tick a leg that judged busbar and passed would produce — the
false green those batteries exist to refuse.

Voice has **nothing to arm against yet**. So the honest report is **PENDING** —
stated per leg, and never dressed up as a conformance pass. Following the MCP
workflow's own guidance, the transition from PENDING to a real armed-or-red leg
is **exercised by `voice-conformance.sh --selftest`** rather than asserted by a
real run that cannot happen. The self-test proves that the moment a leg is marked
`ready` it is held to the same anti-vacuity discipline the other batteries use: a
ready leg that executed nothing is **RED**, not green.

## The two-leg rule (inherited, enforced the day the legs light up)

- **CONTROL runs ALWAYS.** A battery that cannot judge a known-good third-party
  dialect peer cannot be trusted to judge busbar. (Scaffolded today.)
- **SUBJECT is ARMED OR RED.** Once a leg is `ready`, an armed run that executed
  nothing is RED. `--selftest` drives that transition in both directions so the
  rule is one somebody has watched work.

## The legs

Legs are **discovered from `legs/*.sh`, never enumerated** — the same rule
`testing/verdict-covers-every-leg.py` applies to the workflow one level out. Each
`legs/<name>.sh` declares `LEG_KIND`, `LEG_STATUS`, `LEG_SLICES` and a
`leg_execute` function.

| leg | kind | slices | what it will judge |
|---|---|---|---|
| `spec-per-dialect` | conformance | `openai`, `gemini` | the voice spec battery, run once **per dialect** (the matrix) |
| `replay` | conformance | `default` | captured-transcript replay: a recorded session must re-derive identically |
| `cross-parity` | conformance | `oo og go gg` | the **4 ordered** OpenAI⟷Gemini pairs must agree where the mapping says they must |
| `governance` | governance | 5 checkpoints | the 5 vision checkpoints — **NOT a conformance result** |

### The dialect matrix

`spec-per-dialect` runs once per dialect in `{openai, gemini}`. In CI it is a job
matrix; in the runner it is the leg's `LEG_SLICES`. `cross-parity` drives all
four **ordered** pairs — `oo`, `og`, `go`, `gg` — because a mapping that is not
identity *within* a dialect (`oo`, `gg`) is already broken and only running the
cross pairs would never see it.

### Governance is not a conformance result

The `governance` leg observes voice **product policy**, not the voice
**protocol** — barge-in preemption, turn-budget enforcement, metering-lease
settlement (`cost_reserve`/`cost_settle`), dialect down-scope, and the **D2
hard-close-on-exhaustion** checkpoint. Exactly as `testing/a2a-governance/` can
never contribute to the A2A verdict, this leg's findings are **observations**:
the runner enforces the separation in code, and `--selftest` proves a governance
FAIL cannot move the conformance verdict.

## How a leg gets filled (the drop-in)

Edit `legs/<name>.sh`:

1. flip `LEG_STATUS=pending` → `LEG_STATUS=ready`;
2. implement `leg_execute <slice>` to print **one `RESULT <slice> <PASS|FAIL>
   <detail>` line per assertion**.

Nothing in `voice-conformance.sh`, in the verdict emitter, or in
`.github/workflows/voice-conformance.yml` changes. The runner immediately holds
the now-ready leg to the anti-vacuity rule: a `ready` leg that emits no `RESULT`
line for a slice is **RED**.

The inputs later legs consume are authored by another agent and only
**referenced** here:

- `testing/voice-conformance/fixtures/{openai,gemini}/` — captured transcripts
  and per-dialect spec fixtures;
- `docs/design/voice-cross-dialect-mapping.*` — the OpenAI⟷Gemini equivalence
  the `cross-parity` leg is judged against.

## The verdict emitter

The runner's verdict **mirrors `verdict-covers-every-leg.py`** one level in: it
holds the set of legs it *reported on* to equality with the set *discovered*, so
a leg cannot be added to the tree and then silently dropped from the verdict. It
also enforces a **floor** on the leg count (a gutted battery satisfies every
equality) and keeps governance out of the conformance tally. `--selftest` injects
each of those faults through the real emitter and watches the check bite.

## Usage

```bash
# prove the scaffold's own accounting bites, then exit 0
bash testing/voice-conformance/voice-conformance.sh --selftest

# run everything and emit the honest verdict (the default)
bash testing/voice-conformance/voice-conformance.sh --verdict

# one leg (what the workflow's per-leg jobs run)
bash testing/voice-conformance/voice-conformance.sh --leg spec-per-dialect --slice openai
bash testing/voice-conformance/voice-conformance.sh --leg governance

# what is declared
bash testing/voice-conformance/voice-conformance.sh --list
```

## Layout

```
voice-conformance.sh     the runner: --selftest | --verdict | --leg | --list
legs/spec-per-dialect.sh  per-dialect spec leg      (matrix: openai, gemini)
legs/replay.sh            captured-transcript replay
legs/cross-parity.sh      the 4 ordered OpenAI<->Gemini pairs
legs/governance.sh        the 5 vision checkpoints   (NOT a conformance result)
fixtures/{openai,gemini}/ INPUTS authored elsewhere; referenced, not created here
```

The CI workflow is `.github/workflows/voice-conformance.yml`: `gate-selftest`
proves the accounting and the coverage lint bite, one job per leg runs the
scaffolded leg green, and `verdict` asserts every leg executed.
