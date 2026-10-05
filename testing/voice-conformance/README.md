# Voice (streaming-plane) conformance battery

The conformance battery for busbar's **streaming** plane (voice is one dialect inside it, #18), at
structural parity with the sibling MCP (`testing/mcp-conformance/`) and A2A (`testing/a2a-*`)
batteries. It is the streaming plane's conformance MUST-set (DEV-GREEN exit #4).

## What a leg drives: the plane's DOOR, both ways

The plane is served only through its memory-ABI door (`busbar_plane_streaming::door`). Every leg
shells out to one dev-only harness, `busbar-plane-streaming`'s `voice_conform` example
(`crates/busbar-plane-streaming/examples/voice_conform/`), which loads the door through
`busbar-plugin-loader` **both ways** (ARCHITECT Q6):

- **linked** — `busbar_plane_streaming::door::door`, through `load_linked`;
- **dropped** — the `streaming_door` example `cdylib`, dlopened through `load_dropped` against the
  linked row's own Statement.

Each assertion drives a fresh instance of each door with one script and is PASS only when

1. the two doors answered **identically** (a dropped door that is not built or does not load is a
   FAIL, never a skip),
2. the answer passes the leg's check, and
3. **the RED arm bit**: the leg's planted wrong answer (the wrong door, restated as the answer it
   would give) is refused by the same check. `VOICE_CONFORM_RED=1` makes the planted answers the
   subject; every conformance leg must then go RED.

`lib/conform-bin.sh` builds the pair once (`cargo build -p busbar-plane-streaming --example
voice_conform --example streaming_door`); `VOICE_CONFORM_BIN` names a prebuilt harness (checked for
staleness against the plane, loader and contract sources), `VOICE_CONFORM_DOOR` a dropped door that is
not beside it.

## The legs — each judges the DOOR'S half of its seam

Legs are **discovered from `legs/*.sh`, never enumerated**. Each leg's header names what it judges at
the door and which half of the seam is the kernel's (the plane driver's walk, the identity crate, the
money steps, the transport), which a plane cannot see and the harness therefore cannot judge.

| leg | slices | what it judges at the door |
|---|---|---|
| `spec-per-dialect` | `openai`, `gemini` | every fixture: codec round trip, and the door's relay of it by the session rules |
| `replay` | `default` | each captured transcript through one session: codec skeleton; the door's relay and skeleton |
| `cross-parity` | `oo og go gg` | the codec bridge per the cross-dialect map; the bridged wire through the destination door |
| `provider-credential` | 1 | every far request rides a declared outbound need; none carries a credential |
| `metering-lease` | 1 | a session's units, reported per declared class, once per turn; the fee once answered |
| `session-scope` | 1 | the `session` grant kind; every door asks for a principal; 404 off the guest list |
| `gemini-live-route` | 1 | the Gemini Live door: claim, arrival, and the handshake across it |
| `provider-dial` | 1 | a session's far frames ride the dialect's socket need; the host connector dials |
| `admit-refusal` | 1 | a refusal renders in the dialect's shape and opens nothing, dials nothing |
| `route-failover` | 1 | each ATTEMPT answered afresh on the pass need; nothing reaches the caller early |
| `audit-record` | 1 | the audit kind and operation the kernel's one row is written under; no door row |
| `exit-terminal` | 1 | one session, one end; an ended stream is refused on every side |
| `tool-reply` | 1 | a tool call is relayed to the caller and never answered by busbar (Law 11) |
| `governance` | 5 checkpoints | the 5 vision checkpoints — **NOT a conformance result** |

**The session rules** the fixture legs hold the door to (`session_pump`): a caller frame reaches the
far end as sent, except that the caller's session configuration is replaced by the locked one; a
far-end frame reaches the caller as sent, except that usage and rate-limit reports are consumed (usage
becomes reported units), a far-end tool result is never relayed, and a barge-in also cancels and
truncates the far end's response at the audio the caller heard. The expectation is computed from the
wire by the codec, never by the door.

### Governance is not a conformance result

The `governance` leg observes product policy, not protocol. Exactly as `testing/a2a-governance/` can
never contribute to the A2A verdict, the runner keeps a governance FAIL out of the conformance tally,
and `--selftest` proves it.

## The verdict emitter

The runner holds the set of legs it **reported on** to equality with the set **discovered**, enforces
a floor on the leg count, keeps governance out of the conformance tally, and makes a `ready` leg that
emitted no `RESULT` line RED. `--selftest` injects each of those faults through the real emitter and
watches the check bite, then accounts the shipped legs (which runs them: it builds the harness).

## Usage

```bash
bash testing/voice-conformance/voice-conformance.sh --selftest
bash testing/voice-conformance/voice-conformance.sh --verdict          # the default
bash testing/voice-conformance/voice-conformance.sh --leg spec-per-dialect --slice openai
VOICE_CONFORM_RED=1 bash testing/voice-conformance/voice-conformance.sh --verdict   # must be RED
bash testing/voice-conformance/voice-conformance.sh --list
```

## Layout

```
voice-conformance.sh      the runner: --selftest | --verdict | --leg | --list
lib/conform-bin.sh        builds/locates the voice_conform harness and the dropped-in door
legs/*.sh                 one leg each (LEG_KIND, LEG_STATUS, LEG_SLICES, leg_execute)
fixtures/{openai,gemini}/ captured transcripts and per-dialect spec fixtures
```
