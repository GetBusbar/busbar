# VT8 — THE DRIVER'S UPSTREAM SOCKET, and the one leg shape all three dialects go onto

Measured on `keep-streams-driver-socket`, base `6dc9f8192` (`origin/keep-streams-dialects-2`),
merge-base with the integration line `b0c5b6f1`. Every number below was read off this tree with the
command beside it, not carried forward from an earlier note.

This note exists because the work it plans was ordered against `1.6.0-streams-deletion-list.md`
§1e/§1f, and §1e's central sentence — *"the driver owns no upstream socket"* — **is no longer true
and its remedy is no longer the one §1f proposed.** §1g already records the turn; what §1g does not
do is say what is therefore left, because it was written before the dialect cuts landed. This note
is that statement, and it corrects four things a reader of the entries above it would otherwise get
wrong.

---

## 0. THE FOUR CORRECTIONS, before anything is planned

### 0a. THE DRIVER MUST NOT OWN A SOCKET, and that is a decision rather than an omission

The work order says "the driver gains the socket". **The landed design refuses it, in writing, in
the file.** `crates/busbar/src/root/session_driver.rs:437-456`:

```rust
struct UpstreamLeg {
    state: PlaneSessionState,
    lease: Box<dyn EgressLease>,
    unit: UnitIdentity,
    dest: PlaneDestination,
    op: OpClassId,
}
```

with its own header at `:437-444` — *"Three things and no socket, which is the division this whole
line exists for. The SOCKET is the composition's — dialled on the accept task, drained by a future
the root spawned — and what reaches a synchronous `drive` is a bounded `EgressLease`."*

The reason is mechanical and is not a preference. `SessionDriver::drive`
(`session_driver.rs:1236`) is **synchronous**, and it is synchronous so that the arena, the plane
call and the ledger posting all run under one non-awaiting span — a seam that could `await` is a
seam a session's half-written state could be held across. A socket write is not synchronous. So the
driver holds the one thing a synchronous `drive` can reach — a bounded, refusing `EgressLease` —
and the socket is held by the party that can `await`: the composition.

**So "the driver gains the socket" is met, exactly, by the composition gaining one and handing the
driver its offering end.** That is what `attach_leg` (`session_driver.rs:880`) is, and it is already
on the tree. What is missing is not a field on the slot. It is a *caller*.

### 0b. THE UPSTREAM HALF IS ALREADY WHOLE — what is missing is production callers, not machinery

Measured with `grep -rn 'leg_dial\|leg_pump\|attach_leg\|pending_leg' crates/`:

| piece | file | production callers |
| --- | --- | --- |
| the pending leg parked by a unit | `session_driver.rs:1393-1419` | — (internal) |
| `pending_leg` / `attach_leg` | `session_driver.rs:866` / `:880` | **0** |
| `LegDialer` + `LegDialing` decorator | `root/leg_dial.rs:72` / `:96` | **0** |
| `pump_leg` (the leg's inbound half) | `root/leg_pump.rs:56` | **0** |
| `mount::dial_session` (the wire's own dial) | `busbar-transport-ws/src/mount.rs:379` | **0** |
| `mount::address` / `open_session` / `pump` | `busbar-transport-ws/src/mount.rs:175/:237/:416` | **0** on the arrival path |

Every one of those has cells and no caller. `root-duplex-serve` is **default-off**
(`crates/busbar/Cargo.toml:169` does not list it; it is declared at `:247`), so the whole stack is
compiled out of the shipped binary. The landing this note plans adds **no new session machinery at
all**. It adds a composition.

### 0c. `LegDialer` HAS NO PRODUCTION IMPLEMENTOR, and that is the first real gap

`root/leg_dial.rs:72` declares the seam; the only implementor in the tree is `FakeDialler` at
`root/tests/session_driver.rs:1294`. The wire it would be written over exists and is complete —
`busbar_transport_ws::mount::dial_session` hands back exactly the three values `DialledLeg` and
`pump_leg` want, and takes the ownership of the socket whole out of the connection registry so the
session is its single owner. Nothing has to be invented. Something has to be **composed**.

### 0d. THE "TWILIO HAS NO CLAIM" RESIDUAL IS RESOLVED — the deletion list's §1g note is stale

§1g's honest residual says the carrier dialect *"has NO claim and no transport crate … A seam commit
must not mount a carrier leg it cannot claim."* On this tree it has both:

* the claim: `crates/busbar-plane-streams/src/claims.rs:209-212` — `twilio-media-streams` on
  `WS_TRANSPORT`, selector `PrefixOneLevel("/v1/realtime/telephony")`, scheme alt
  `twilio-signature`. The file's own header at `:20-26` records the return: *"THE CARRIER CLAIM IS
  BACK, ON `WS_TRANSPORT`. It was dropped because it named a wire with no crate … So the claim comes
  back on the wire that was always underneath it."*
* the binding: `crates/busbar-plane-streams/src/surface.rs:86` / `:151` — `BINDING_CARRIER`, mount
  `/v1/realtime/telephony/{call_id}`, `Bar::Credential`.
* the crate: `busbar-plane-streams-twilio`, registered at `root/registry.rs:509-546`.

§1g also spells the dialect as `Dialect::TwilioMediaStreams` — **an enum variant that no longer
exists.** The `Dialect` enum was replaced by the string-keyed row table
(`busbar-plane-streams/src/dialect.rs:124-157`, registered at runtime). The third leg is mountable.

---

## 1. THE SOCKET: where it is opened, and what opens it

### 1a. It is opened through a ROOT-COMPOSED EGRESS PORT, keyed by the plane's decl

PLANEDECL-3 gave `BuildCtx` a `composed` slice — root-composed ports keyed by the plane decl's own
`config_section` (`busbar-substrate/src/plane/registry.rs:58-73`, read at `:113-121`). Today it
carries **exactly one** entry, written at `crates/busbar/src/main.rs:1316-1335`:

```rust
(busbar_voice::PLANE_DECL.config_section, Arc::new(voice_calls) as Arc<dyn Any + Send + Sync>)
```

`config_section` is `"streams"`. `GovernedCalls` has two methods — `replied` and `expired`
(`busbar-plane-streams/src/governed.rs:50`/`:57`) — and neither opens anything. **There is no egress
port.** That is the port this landing adds, and the key is the same key: the decl's, not a plane's
name spelled in the root.

**Why a composed port and not a call.** The composition root registers its wire in exactly one place
— `kind-isolation:transport-registration` is the rule, and it is green — and a second place that
named `WsTransport` by its concrete type would be a second registration in everything but the word.
So the root builds the dialler once, off the seal it already registered the wire on
(`registry::seal(..).transports.ws`, the same allocation `plane_mount`'s seventh cell asks for by
identity), and hands it across as a port. `leg_dial.rs`'s own header says the same thing from the
other side: *"What dials is a WIRE, and this module names none."*

### 1b. The shape, end to end, for ONE session

```
   client upgrade  ─┐
                    │  root arrival spec  (root/ws_arrival.rs — NEW)
                    │    mount::address(SURFACE, key, chain, &Upgrade)     ← addresses off the row
                    │    mount::open_session(driver, SURFACE, &mount, &up) ← OPENING UNIT, pre-upgrade
                    │    duplex_ws::accept_coded(..) ──► (Receiver, Sender, CloseSlot)
                    │    mount::pump(driver, session, LegDialing(src), sink, budgets)
                    │                         │
                    │                         └── between frames: dial_pending
                    │                                  LegDialer::dial(session, dest)
                    │                                    └─ mount::dial_session(ws, dest, keys, media, depth)
                    │                                         ├── FrameSource ──► spawn pump_leg(driver, session, src)
                    │                                         ├── EgressLease ──► driver.attach_leg(session, lease)
                    │                                         └── drain      ──► spawn
```

Three ownerships, three places, and each is already written down where it belongs:

* the **offering** half reaches the synchronous `drive` as a lease — `attach_leg`, `:880`;
* the **inbound** half is a loop for the life of the session — `pump_leg`, and it is the *dialler's*
  to start, which is why `LegDialer::dial` is handed the `SessionHandle` (`leg_dial.rs:74-80`);
* the **drain** is returned rather than spawned, so the wire does not choose the root's runtime
  (`mount.rs:355-358`).

### 1c. WHEN the dial runs, and why "between frames" is exact rather than approximate

`LegDialing` decorates the `FrameSource`, so the dial runs inside `next_frame`, in the gap between
two frames of the strict alternation `mount::pump` enforces (read one, drive it, write the answer,
read again). The frame whose unit **sealed** the leg has already been driven and answered before the
next read begins, so the dial completes strictly before any frame that could need the leg is read —
zero frames in flight across it, by the shape of the loop rather than by a lock
(`leg_dial.rs:14-23`). A dial that fails returns `Err(Closed)` to the pump and ends the session; the
alternative — a leg that never opened, relaying nothing while the client keeps talking — is a
relayed session that silently stopped relaying.

---

## 2. ONE LEG SHAPE FOR ALL THREE DIALECTS

The work order asks for "one leg shape for all three dialects (sideband / telephony / gemini are
dialect rows + the transport's arrival spec, not three code paths)". That is what the tree already
declares; the measurement is below.

### 2a. Today busbar-voice has THREE code paths, and they are visibly three

`busbar_voice::mount::ws_accept` (`mount.rs:1250-1508`, 259 lines) dispatches on its own
`pub(crate) enum Ingress` (`mount.rs:612-626`) into three differently-shaped arms:

| arm | lines | shape |
| --- | --- | --- |
| `Telephony \| Gemini` + provider | 1379-1425 | `open_admitted_telephony` → `dial_provider` → `TelephonyProxy::run` |
| `Telephony \| Gemini`, no provider | 1432-1459 | `open_admitted_session` → `UplinkForwarder` into a dropped receiver |
| `Sideband` | 1462-1499 | `open_admitted_session` → `ServedSession`, first frame written by hand |

Three arms, three session types (`TelephonyProxy`, `UplinkForwarder`, `ServedSession`), two
open functions, and a vendor branch for the provider URL (`provider_ws_url`, `mount.rs:1163`) whose
only reason to exist is that one vendor puts the key in the query string (`redact_url_credentials`,
`:1189`).

### 2b. On the driver there is ONE, and the difference between the three is DATA

Everything that differs between the legs is already declared as a row, and the driver already reads
every one of them as data:

| what differs | where it is declared, as data | who reads it |
| --- | --- | --- |
| the URL a leg is served on | `surface.rs:142/:151/:160` — three `BindingDecl` mounts | `mount::address` |
| the credential bar | `surface.rs:183/:188/:196` — `Bar::Credential` on all three | `open_session` (`:1152`) |
| the frames' media | `surface.rs:94` — `MEDIA_JSON`, one constant both directions | `declared_run` (`:182`) |
| how a frame is read | `Dialect::reader` (`dialect.rs:147-153`) | the plane's `decode_ingress` |
| how a frame is written | `Dialect::writer` (`dialect.rs:154-156`) | the plane's `encode_*` |
| does this leg dial upstream at all | `Dialect::duplex_upstream` | `SessionUnits::destination` |
| is the posture µ-law-locked | `Dialect::locked_session_config` | `session_params` |
| does the dialect meter its own uplink | `Dialect::meters_own_uplink` | the metering step |

`reader: None` / `writer: None` is a **declared answer, not a gap** — it means "the shared duplex IR
reads this dialect's frames", which is why openai-realtime carries `None` for both and gemini-live
carries `Some`. The carrier carries an `Envelope` instead, because its frames are an envelope around
the same IR.

**So the arrival specs are built by walking `SURFACE.bindings` — three rows in, three specs out — and
there is no arm.** A fourth dialect is a fourth row and a fourth registration
(`root/registry.rs:509`), and not a fourth code path. This is the whole content of "every plane
identical": the streams plane's session goes through the same Teller loop every other plane's unit
goes through, and the driver is the plane's leg.

### 2c. The one asymmetry, and it is declared

`twilio-media-streams` carries `duplex_upstream: false` — *"ingress only: this plane serves, never
dials"* (`busbar-plane-streams-twilio/src/lib.rs:376`). Its sessions therefore never park a pending
leg, so `LegDialing` never dials for them and `pump_leg` is never spawned. That falls out of the
row; the mount does not test for it. This is exactly the shape §1e's table was reaching for when it
said `Sideband` could be served and the other two could not — except the axis is not the leg, it is
the row, and the row already says it.

---

## 3. WHERE THE SESSION'S FRAMES ARE METERED

**One inbound frame is one unit.** Not a byte count, not a turn, not a second of audio — a frame,
because that is the granularity at which a refusal is still answerable and at which a session's
identity can be carried.

The plane declares the classes (`busbar-plane-streams/src/meta.rs:187-200`):

* `voice.session.open` — `OP_SESSION_OPEN`, the class the **opening unit** is priced and audited
  under. That unit runs inside `mount::open_session`, **before the protocol changes**, which is the
  one moment a refusal can still be answered as an HTTP status rather than as a close code. A
  session that cannot be paid for is refused where the client can still read the reason.
* `duplex_turn` — the class every frame inside an open session is priced under, for all three
  dialects (the doc at `:190-195` says so: *"a duplex turn (the unit shape for the two duplex
  dialects and for telephony, which is ingress-only into one)"*).
* `transcribe` / `tts` — the one-shot HTTP operations, not on this path.
* the provider tool call — what a `Progress::OneShot` pushed mid-session by a provider is priced as.

**The identity on every unit is THAT session's.** `session_driver.rs` builds the unit's
`UnitIdentity` per frame with `origin: Origin::Client`, `direction: Direction::Outbound`, and
`principal: self.units.principal(session.0)` (`:1393-1419`) — the principal the composition's own
authenticate step resolved, off the same settlement the destination comes off. That is what links a
session's postings and its audit records to the session rather than to nobody, and it is the reason
the relay's writes can be a *unit's* writes at all: `encode_egress` / `encode_ingress_frame` /
`encode_end` take a `busbar_contract::unit::Unit<'u>`, and the kernel's unit-view seam is what mints
one against the identity the loop already sealed.

**The leg's inbound direction is metered too, and through the same loop.** `driver.upstream`
(`:979-1092`) decodes the provider's frame against the leg's codec state, re-encodes it against the
client's, and a provider **push** — a tool call the provider opened — goes through the full unit
loop at `:1073-1090` rather than being relayed unpriced. A relay that metered only the client's half
would let the expensive direction through free.

**What the root must NOT do here.** `plane-no-money` is a gate row and it is currently red for
`busbar-llm` only (8 `priced` symbols in `crates/busbar-llm/src/unit/`). The streams plane names
usage classes and quantities and never a price, and the arrival mount must keep it that way: the
mount composes, the kernel settles, and `one-pricing-site` stays green.

---

## 4. WHAT OF `busbar-voice` DIES, IN WHICH COMMIT

### 4a. THE THREE LEGS ARE ONE COMMIT, NOT THREE — and the work order's "one commit each" is refused

The work order asks for "the three legs move onto it in one commit each". **The deletion list refuses
that in three separate places and the refusal is load-bearing**, so this note follows the document
the work order told it to read first:

* §1e: *"mounting it on `Sideband` ALONE deletes nothing … `VoiceSession` … and `UplinkForwarder` are
  both held by `topology::telephony` as the proxy's downlink and uplink planes … and
  `open_admitted_session` is reached from the no-provider fallback as well as from `Sideband`. A
  sideband-only mount leaves every one of them live, so it is a second serving path beside the one
  that ships — build-beside-legacy, with no deletion to pay for it."*
* §1f: *"the three legs move onto the driver together, and `VoiceSession`, `UplinkForwarder`,
  `open_admitted_session`, `TelephonyProxy`'s two planes … all go in that one commit, because they
  are one path and not six."*
* §2b: *"THE ONE LINE THAT KILLS BOTH: the commit §1f/§1g name — the three legs moving onto the
  driver TOGETHER."*

The measurement confirms it. `voice_ws_arrivals` (`mount.rs:574-606`) builds all three specs and
`register_ws_arrivals` (`main.rs:756-762`) installs the **vector**; there is no per-leg
registration to move one at a time. Both `Telephony` and `Gemini` land on the same two arms of
`ws_accept`. And `ws_accept` itself is one function, `pub(crate)`, with all five `Ingress` variants
in its signature's reach: it cannot lose one arm without the other two, because the two it would keep
are the ones that construct the types the third one's deletion is supposed to pay for.

A per-leg commit is therefore a commit that **adds a serving path and deletes nothing** — the exact
thing "delete legacy, never build beside" names. The commits below are what this landing is.

### 4b. The commits

| # | class | what lands | what of `busbar-voice` dies |
| --- | --- | --- | --- |
| 1 | design | this note | nothing |
| 2 | seam | the root's **egress port**: a `LegDialer` over `mount::dial_session`, built off the boot seal's registered `ws` wire, handed across `composed_ports` keyed by `PLANE_DECL.config_section`. Red-first cells over a lease that is nobody's. | nothing — and that is correct: a dialler with no mount serves no byte and un-serves none |
| 3 | seam | the root's **gauntlet seam** (§1g item 2) — the composition supplies a `GauntletPlane`, the same shape `LegDialer` is, because `accept_gauntlet` takes one and the root has none | nothing |
| 4 | **the one commit** | `root/ws_arrival.rs`: specs built off `SURFACE.bindings`, `address`/`open_session` pre-upgrade, `accept_coded` for the close code, the channel adapter, `LegDialing` + `pump_leg`, the operator gate/tap over `SessionParams`, `ComposedUnits` wired into `ProductionUnits::with_duplex_units`, `root-duplex-serve` **default ON** | see 4c — all of it, in this commit |

### 4c. What dies in commit 4, measured (`grep`-verified call sites, all in `crates/busbar-voice/src`)

| name | file:lines | prod lines | why it dies here |
| --- | --- | --- | --- |
| `ws_accept` | `mount.rs:1216-1508` | 293 | the root arrival is its replacement |
| `Ingress::{Sideband,Telephony,Gemini}` | `mount.rs:612-626` | 3 variants + ~14 arms | all three duplex variants at once |
| `voice_ws_arrivals` | `mount.rs:574-606` | 33 | `register_ws_arrivals` stops calling it |
| `provider_ws_url` | `mount.rs:1163-1175` | 20 | sole caller `:1393` |
| `redact_url_credentials` | `mount.rs:1189-1213` | 37 | sole caller `:1417` |
| `GEMINI_PATH` / `GEMINI_MOUNT_PATH` / `GEMINI_API_KEY_HEADER` | `mount.rs:210/:215/:180` | ~15 | the mount is the plane's row now |
| `VoiceMount::gemini_provider` + accessor | `mount.rs:250/:286-290` | ~8 | sole non-test reader `:1362` |
| `VoiceSession<C>` | `runtime/session.rs:635-692` | 58 | the driver's per-frame client read replaces it |
| `UplinkForwarder<C>` | `runtime/session.rs:694-729` | 36 | the relay is `driver.upstream` |
| `ServedSession<C>` | `runtime/session.rs:535-579` | 45 | sole construction `mount.rs:1496` |
| `serve_with_sweep` | `runtime/session.rs:601-621` | 21 | three callers, all in `ws_accept` |
| `open_admitted_session` | `topology/mod.rs:333-408` | 76 | three callers, all dying here |
| `open_admitted_telephony` | `topology/telephony.rs:126-170` | 45 | sole caller `mount.rs:1380` |
| `TelephonyProxy<C>` (struct + `run`) | `topology/telephony.rs:45-63`, `:172-261` | 109 | its two planes are the two above |
| `begin_telephony` | `topology/telephony.rs:69-113` | 45 | last caller `mount.rs:742` discards the result |
| `SessionGauntlet` | `topology/mod.rs:234-262` | 29 | the root supplies the gauntlet (commit 3) |
| `bind_served_session` + `NEXT_SERVED_SESSION` | `mount.rs:160-175` | 16 | sessions are the driver's now |
| `GEMINI_LIVE` (the underscore spelling) | `lib.rs:163` | 1 | the last underscore spelling in the tree |
| `compose_voice_governed_calls` | `busbar/src/main.rs:845-879` | 35 | every served session is the composition's |
| `NodeCalls` + its `GovernedCalls` impl | `root/units_voice.rs:629-684` | 56 | sole construction was `main.rs:878` |

Roughly **~980 production lines of `busbar-voice` plus ~91 of the root**, against a mount this note
estimates at 400-500. **Net-negative on the tree, and that is the condition on the commit**: if the
mount comes out larger than what it deletes, it is not a replacement, it is a second implementation
with the first one's corpse beside it.

### 4d. WHAT SURVIVES, and the one line that kills it

`busbar-voice` does **not** die in commit 4, and saying otherwise would be the same over-claim §2b
already corrects. What survives:

* the **one-shot HTTP legs** — `Ingress::{Mint, Sdp}`, `voice_routes` (`mount.rs:542-563`),
  `topology/minter_https.rs` (161), `topology/webrtc.rs` (155), `open_governed`/`finish`/`TurnMeter`.
  These are `/v1/realtime/client_secrets` and `/v1/realtime/calls`, and no duplex mount serves them.
* `ToolExecutor` — the tool moat, which runs a tool in-process and authors the
  `function_call_output` itself. §1e is still exactly right about this one: *"The root has the second
  half and not the first."* The composed table says a CLIENT answered; nothing on the root's side
  runs a tool.
* `busbar-voice-codec`'s `topology::twilio` (391 + 270 of cells), still behind a `runtime` feature
  nothing turns on.
* `config.rs` (205), the scope policy, the metering and the carrier runtime.

**The one line that kills the rest**: the one-shot planes moving onto the plane's own declared
`Unary` operations, and `ToolExecutor` getting a declared seam on the root's side. Neither is this
landing's, and neither is blocked by it.

---

## 5. THE RATCHET, MEASURED — including the one thing everybody has got wrong

### 5a. The base is RED and this landing inherits it

| gate | verdict at `6dc9f8192` | what |
| --- | --- | --- |
| `cargo check --workspace --all-targets` | green | — |
| `config-schema` | green, 5 rows | — |
| `kind-isolation` | **RED** | `matrix` only: 4 `minted-row` findings — `busbar-plane-streams-gemini × codec`, `busbar-plane-streams-twilio × {codec, plane, transport}`. All ten other rows PASS. |
| `construction` | **RED**, 16 rows | the twelve the base carried plus the four `8fc937495` recorded (`manifest-allowlist` and `source-denylist` ×2 crates). `ceiling-rose` carries 9 findings; `ceiling-slack` PASSES. |

The four `minted-row` findings are the dialect-crate cuts' own, and `8fc937495`'s message already
states the door they are owed: *"T0-F's `[[minted]]` door, which is not on this base"*. **This
landing must not add a fifth.** Any rise it needs must be on a row that exists at `b0c5b6f1`, through
`[[gate.ceiling_raises]]`.

### 5b. THE `dialect` COLUMN IS UNRATCHETED, and the previous reading of it was wrong

`8fc937495` struck two declared raises on `cell.busbar.dialect.count` because `ceiling-rose` refused
them as *"not a rise at the base"*. It is worth writing down precisely what that means, because the
natural reading — "so a rise there is blocked" — is the opposite of the truth and would stop this
landing for no reason.

Measured:

```
$ git show b0c5b6f1:qa/kind-isolation.toml | grep -c 'kind = "dialect"'
0
```

**The `dialect` KIND COLUMN DOES NOT EXIST AT THE MERGE-BASE AT ALL** — not for `busbar`, not for
anyone. The kind went live on this branch. So `cell.busbar.dialect.count` (today `651`) has no
`before`, and `ceiling-rose`'s arithmetic — *"a key with no `before` has nothing to be higher than"*
— means it reports **no finding** when the number moves. It is not that a rise is refused; it is
that a rise is **invisible**. Confirmed on this tree: `ceiling-rose`'s 9 findings do not include
`cell.busbar.dialect.count`, and the `matrix` gate's 4 `minted-row` findings do not either.

That is the hole `[[minted]]` exists to close and it is genuinely open here. The honest posture for
this landing is therefore **not** "the column is free", it is: the column will move, `ceiling-slack`
will require it re-pinned to the measurement, no gate will say a word, and **the commit message must
say the number and why**, because the commit message is the only ratchet that column has. A landing
that let it drift silently because the gate could not see it would be using a known hole.

The columns that **are** ratcheted and will need declared raises, each measured rather than
predicted at the commit that moves it: `cell.busbar.plane.count` (1858), `cell.busbar.transport.count`
(1042), `cell.busbar.control.count` (1091), `cell.busbar.kernel.count` (176),
`cell.busbar.contract-transport.count`. `busbar` is a WIRE-PERMITTED kind — the one place in the tree
allowed to name what it composes — which is why it may declare and a plane crate may not.

### 5c. `legacy-reach` must fall, not hold

`legacy-reach:busbar_core`, `:busbar_llm`, `:busbar_substrate` and the total are all PASS at the base
and are one-way ratchets. Commit 4 deletes a root write (`compose_voice_governed_calls`) and adds a
root mount that reaches `busbar_substrate::ingress::duplex_ws::accept_coded`. **That is a rise in
`busbar_substrate` reach and the gate will refuse it.** The answer is not a declaration — it is that
the arrival path is the one `busbar_core::router` already drains (`take_ws_arrivals`), so the mount
is installed through the same `install_ws_arrivals` the voice plane uses today and the root's reach
into the substrate does not grow by a call it did not already make. If the measurement says otherwise
at commit 4, the mount is wrong and not the gate.

---

## 6. THE RECORDING, AND THE NAMED GAP

The work order conditions the streams golden cells on *"the pinned tool if `oracle.pin` on your base
carries the ws recorder (>= 0.3.12)"*. Measured:

```
$ cat testing/shadow-oracle/oracle.pin
tag=v0.3.7
sha256=157b30e2ce3852d2e66b7c1fce3400025e285e9b0c23dca0cce78f9d46ce0975
```

**`v0.3.7` < `0.3.12`. The pinned oracle does not carry the ws recorder.** The second half of the
measurement agrees and is independent of the version number: the cell vocabulary in
`testing/shadow-oracle/cells/__init__.py` has constructors `http(...)` (`:308`), `exec_(...)`
(`:318`) and `concurrent(...)` (`:1235`) **and no websocket constructor at all**, so there is no
shape in which a streams session cell could be spelled even if the tool were newer. The existing
streams-adjacent cell is `neutrality|routes|voice-shaped-404` (`:1508`), an HTTP GET asserting the
realtime path is *unmounted* when no `streams:` block is configured.

**So the streams golden cells stay `needs_fixture`, and the gap is named**: they are owed a pin move
to a shadow-oracle that carries a ws recorder — `testing/shadow-oracle/oracle.pin`, `tag` and
`sha256` both, per the file's own "To move the pin" instruction — plus a `ws(...)` cell constructor
beside `http(...)`. `needs_fixture` is the mechanism already in the file for exactly this
(`cells/__init__.py:231/:245/:255/:280/:445`), and a cell recorded against a recorder that cannot
open a socket would be a cell that passed by not asking.

Recording, when the pin moves, is `scripts/prove-remote.sh` on a fleet on-demand box — never the
runner's box — with `.keep-proof.toml`'s `families` and `tests` as scoped. Note the file's own
warning that `tests` must stay on **one line**: both readers take it with a single-line `sed`, and a
pretty-printed array is read as no packages and widens the run to the whole workspace.

---

## 7. THE ORDER, AS ONE LIST

1. **This note.** (commit 1)
2. **The egress port** — `LegDialer` over `mount::dial_session`, off the boot seal's wire, across
   `composed_ports` keyed by `PLANE_DECL.config_section`. Red-first, cells over a nobody's lease.
   Deletes nothing, and must not pretend to. (commit 2)
3. **The gauntlet seam** — the composition's `GauntletPlane`, §1g item 2, the last of the three
   §1g blockers still open (items 1 and 3 are CLOSED: `SessionParams` and `channel_coded`/`accept_coded`
   are both on this tree). (commit 3)
4. **The one commit** — `root/ws_arrival.rs`, the three legs together, `root-duplex-serve` default
   ON, and every name in §4c deleted in the same commit. Net-negative or it is not a replacement.
   (commit 4)

Nothing here is blocked on the arena, the wire, the registration, the drain, the driver, the hook
face or the close code. All four remaining items are compositions, and the tree has a declared seam
for each.
