# Voice (streaming-plane) conformance battery

The conformance battery for busbar's **streaming** plane (voice is one dialect inside it, #18), at
structural parity with the sibling MCP (`testing/mcp-conformance/`) and A2A (`testing/a2a-*`)
batteries. It is the streaming plane's conformance MUST-set (DEV-GREEN exit #4).

## What a leg drives: the plane's DOOR, both ways

The plane is served only through its memory-ABI door (`busbar_plane_streaming::door`). Every leg
shells out to one dev-only harness, the `voice_conform` binary of the testkit crate
`voice-conformance-harness` (`testing/voice-conformance/harness/`), which loads the door through
`busbar-plugin-loader` **both ways** (ARCHITECT Q6):

- **linked** — `busbar_plane_streaming::door::door`, through `load_linked`;
- **dropped** — the plane's cdylib twin (`busbar-plane-streaming-plugin`), dlopened through
  `load_dropped` against the linked row's own Statement.

Each assertion drives a fresh instance of each door with one script and is PASS only when

1. the two doors answered **identically** (a dropped door that is not built or does not load is a
   FAIL, never a skip),
2. the answer passes the leg's check, and
3. **the RED arm bit**: the leg's planted wrong answer (the wrong door, restated as the answer it
   would give) is refused by the same check. `VOICE_CONFORM_RED=1` makes the planted answers the
   subject; every conformance leg must then go RED.

`lib/conform-bin.sh` builds the pair once (`cargo build -p voice-conformance-harness --bin
voice_conform`, and the cdylib twin at the rev the root pins the plane, in this workspace and so
against the host's busbar-contract: `cargo build --locked -p busbar-plane-streaming-plugin`); `VOICE_CONFORM_BIN` names a prebuilt harness (checked for staleness
against the plane, loader, contract and harness sources), `VOICE_CONFORM_DOOR` a dropped door that
is not in the profile directory beside it.

## The legs — each judges the DOOR'S half of its seam

Legs are **discovered from `legs/*.sh`, never enumerated**. Each leg's header names what it judges at
the door and which half of the seam is the kernel's (the plane driver's walk, the identity crate, the
money steps, the transport), which a plane cannot see and the harness therefore cannot judge.

| leg | slices | what it judges at the door |
|---|---|---|
| `spec-per-dialect` | `openai`, `gemini`, `twilio` | every fixture: codec round trip, and the door's relay of it by the session rules; the `twilio` slice also replays `transcript.jsonl`, one whole call |
| `replay` | `default` | each captured transcript through one session: codec skeleton; the door's relay and skeleton |
| `cross-parity` | `oo og go gg` | the codec bridge per the cross-dialect map; the bridged wire through the destination door |
| `provider-credential` | 1 | every far request rides a declared outbound need; none carries a credential |
| `metering-lease` | 1 | a session's units, reported per declared class, once per turn; the fee once answered |
| `session-scope` | 1 | the `session` grant kind; every door asks for a principal; 404 off the guest list |
| `gemini-live-route` | 1 | the Gemini Live door: claim, arrival, and the handshake across it |
| `provider-dial` | 1 | a session's far frames ride the dialect's socket need; the host connector dials |
| `admit-refusal` | 1 | a refusal renders in the dialect's shape and opens nothing, dials nothing; a policy refusal wears its 4xx, never `server_error` |
| `route-failover` | 1 | each ATTEMPT answered afresh on the pass need; nothing reaches the caller early |
| `audit-record` | 1 | the audit kind and operation the kernel's one row is written under; no door row |
| `exit-terminal` | 1 | one session, one end; an ended stream is refused on every side |
| `tool-reply` | 1 | a tool call is relayed to the caller byte for byte and never answered by busbar; the turn's usage report reaches the caller too, and is reported as units (Law 11, Law 5) |
| `twilio-route` | 1 | the Twilio claim: ws transport, one-level `/twilio` prefix, `webhook-signature` the only alternative, a principal asked for; the session opens on the `event`-tagged `start` frame |
| `twilio-media` | 2 | inbound `media` is the caller's audio; `start` locks the far end in µ-law and sends it nothing else; the far end's audio is written back as `media` on the call's `streamSid`, a barge-in as `clear`, and its end sends the far end nothing; `stop` ends the session once; a far end's tool call reaches the Twilio caller as-is (Law 11) |
| `twilio-metering` | 1 | a Twilio session's units, reported per declared class once per turn, the open turn settled when `stop` arrives mid-turn |
| `governance` | 5 checkpoints | the 5 vision checkpoints — **NOT a conformance result** |

**The session rules** the fixture legs hold the door to (Law 5, `BUSBAR-1.6.0.md` l.1903; Law 11,
l.2127-2136): a caller frame reaches the far end as sent, except that a frame configuring the session
or asking for a response takes the session's locked keys (the governed byte-level splice); every
far-end frame reaches the caller as sent, a tool call and a usage report included (a usage report also
becomes reported units); busbar sends the far end nothing on the caller's behalf. The door's frames
are compared byte for byte with the frames the rules owe each side, in order; the expectation is
computed from the wire, never by the door.

### The Twilio legs

Twilio is a dialect over the `ws` transport, claimed on a one-level `/twilio` path prefix
(`BUSBAR-1.6.0.md` l.418-419; first billable streaming cut with OpenAI and Gemini, #45). Its inbound
auth is `busbar-auth-webhook-signature`, variant twilio: HMAC-SHA1 `X-Twilio-Signature`, scheme
alternative `webhook-signature`; a missing signature is 401 end to end and Twilio carries no replay
rule (l.847-852). Every Twilio frame is `event`-tagged JSON. The fixtures in `fixtures/twilio/` are
transcribed from Twilio's published messages
(<https://www.twilio.com/docs/voice/media-streams/websocket-messages>), one file per message:
`from-twilio.{connected,start,media,dtmf,mark,stop}.json` (what Twilio sends busbar; `mark` is
Twilio's echo of a mark a sender wrote) and `to-twilio.{media,mark,clear}.json` (what a sender may
write Twilio), plus `transcript.jsonl` (one call: `client` is Twilio to busbar, `server` busbar to
Twilio). No spec line asks busbar to write Twilio a `mark` (THE DESIGN §2 l.418-419, Part 2 #45), so
the legs read the `mark` fixtures through the codec and take no position on what the caller is told
when the far end's audio ends; they require only that the far end is sent nothing for it.

The legs are written to the spec and to Twilio's formats, not to what the reader does today, and
they go GREEN only when the streaming plane answers them. The telephony session's far end is the
realtime dialect locked to `g711_ulaw`, so the far end's events are the OpenAI Realtime ones
(`response.output_audio.delta`, `response.output_audio.done`, `input_audio_buffer.speech_started`).
The kernel's half of the Twilio seam (the boot admitting the claim, the 401 on a missing signature,
the HMAC-SHA1 verify) is not judged here.

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
fixtures/{openai,gemini,twilio}/ captured transcripts and per-dialect spec fixtures
```
