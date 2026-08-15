# TCK requirements busbar does not meet, and why — recorded, not hidden

Every entry here names a requirement the official suite reports as FAILED against busbar, the method
by which that was established, the reason it is not being made to pass, and the date. A requirement
that is failing for a reason nobody wrote down is indistinguishable from one nobody noticed, which
is the whole point of this file.

Read alongside `scripts/a2a-subject/boot.sh` (which produces the number) and `run-tck.sh` (which
runs the suite). **Nothing here silences a test.** Every waived requirement still runs, still fails,
and is still counted in the suite's own MUST row.

**`testing/a2a-tck/subject-waivers.json` is the machine-checkable PIN of exactly one entry from
this file's ledger** — the LOCKED `PUSH-DELIVER-001/002/003` trio — and it is what
`scripts/a2a-subject/boot.sh`'s `assert_tck_number` gates the subject leg on, at the
REQUIREMENT level (not the suite's own MUST row, which folds `NOT TESTED` requirements — a suite
limitation shared by the pinned third-party control, see `check-baseline.py` and
`testing/a2a-tck/baselines/` — into "failed" and is printed for a human but not gated on).
`CARD-EXT-001` and `GRPC-ERR-001` were both deliberately absent from that pin while they failed —
they failed the subject leg's gate, named, on every run, exactly as this file said they should —
and BOTH ARE NOW FIXED (2026-08-15; their entries below record what changed). The gate expects
them green.

---

## The 21 untested MUSTs — recorded 2026-08-14, not waivers, TCK-coverage impossibilities for anyone

**These 21 are not a busbar waiver. They are requirements the pinned TCK itself never tests, for
any implementation.** The denominator this file's own PUSH-DELIVER entry and every other document
in this repo quotes — **93, not 114** — is 114 minus exactly these:

```
AUTH-INTASK-001  AUTH-INTASK-002  AUTH-INTASK-003  AUTH-INTASK-004
AUTH-SCOPE-001   AUTH-SCOPE-002   AUTH-SCOPE-003
AUTH-SERVER-002
AUTH-TLS-001
BIND-EQUIV-001   BIND-EQUIV-002   BIND-EQUIV-003   BIND-EQUIV-004
CARD-SIGN-001    CARD-SIGN-002    CARD-SIGN-003    CARD-SIGN-004
VER-CLIENT-001   VER-CLIENT-002
VER-SERVER-001
GRPC-SVC-003
```

**METHOD.** `grep -rl` over the pinned TCK's own `tests/` tree (`5996b79f9cefa6fc390980e383e358a66fb9e49e`)
returns nothing for any of the 21: `test_ids: []`, `transports: {}` in the requirement's own entry.
The suite's summary table counts them among the FAILED requirements; its JSON report calls them
`NOT TESTED`. Those two readings disagree about the same 21 rows, which is how the gap was found
rather than assumed.

**CONTROL-SUITE EVIDENCE, so this is not read as a busbar defect.** The identical 21 come back
`NOT TESTED` against the publisher's own reference implementation, `a2a-go` v2.4.0, on both bindings
this repo pins:

```
a2a-go v2.4.0 / jsonrpc     NOT TESTED: 26    PASS 50  FAIL 28  SKIPPED 25
a2a-go v2.4.0 / http-json   NOT TESTED: 27    PASS 46  FAIL 27  SKIPPED 29
```

The same families come back untested against the A2A project's own Python SDK agent too. The
suite's own backlog admits the gap: three open `coverage-gap` tasks, all status **To Do** —
`task-27` (`AUTH-*`, 13 requirements), `task-28` (`BIND-EQUIV-*`, 4), `task-29` (`CARD-SIGN-*`, 4).
`testing/a2a-supplement/` covers all 21 with busbar-authored checks (reported separately, never
added to the TCK's own number — see `testing/a2a-supplement/README.md`), and 17 of the 21 discriminate
against at least one control there.

**WHY THIS IS NOT A WAIVER.** A waiver excuses busbar from a requirement busbar could in principle be
tested against. These 21 cannot be tested against **anyone** through this pin — there is no green or
red to waive, only an absent measurement. Recording them here is the same discipline as a waiver
(named, dated, with evidence) applied to a different failure mode: a suite that never ran, not a
control that fired.

**DENOMINATOR.** `114 − 21 = 93`. That is the achievable ceiling on this pin, and the target is 100%
of it. 3 of the 93 (`PUSH-DELIVER-001/002/003`, below) are a deliberate security refusal — busbar
never accepts a plaintext webhook callback — waived-red permanently, never a gap. Public claim:
**90/93** (2026-08-15, `CARD-EXT-001` and `GRPC-ERR-001` fixed; the only remaining reds are the
PUSH-DELIVER trio, which is the security refusal above — the number does not go higher on this pin
without accepting plaintext callbacks).

**WHAT WOULD RETIRE THIS ENTRY.** The pinned TCK growing a second credential (for the `AUTH-*`/scoping
families) and an upstream vantage point (for `VER-CLIENT-*`) — see "Upstreaming" in
`testing/a2a-supplement/README.md` — and re-pinning at a commit that carries tests for these 21.
Until then this is a property of the suite, not of busbar, and is recorded rather than chased.

---

## `PUSH-DELIVER-001` / `PUSH-DELIVER-002` / `PUSH-DELIVER-003` — waived 2026-08-12

**METHOD.** `scripts/a2a-subject/boot.sh --tck` against a busbar built from this commit, TCK pinned
at `5996b79f9cefa6fc390980e383e358a66fb9e49e`. MUST row from the suite's own stdout:

```
│ MUST        │     73 │     25 │      16 │   114 │
```

All three appear in the suite's `FAILED REQUIREMENTS` list with one refusal, verbatim:

```
✗ PUSH-DELIVER-001 (jsonrpc): 'Skipped: send_message failed: push callback scheme `http` is
  refused; a callback carries task metadata off-box and must be https'
```

**REASON — and it is NOT the one previously recorded.** The standing note said these three fail
because the rig runs the TCK's webhook receiver on loopback and busbar's SSRF guard correctly
refuses a caller-supplied loopback webhook, so the fix was to make the receiver non-loopback. That
diagnosis is wrong about which check fires, and fixing the topology alone would change nothing.
Three independent blockers stand in front of these requirements, in this order:

1. **THE SCHEME, and it is decided before any address is looked at.** `tck/webhook/server.py`
   builds its URL as `f"http://{webhook_host}:{self.port}/webhook"` — the scheme is a literal and
   the only knob the suite exposes is `--webhook-host`, which substitutes the HOST. busbar refuses a
   plaintext webhook: `a2a::pushnotify::structural_check` tests the scheme first and returns
   `Scheme("http")` before the host is parsed for ranges, which the unit test
   `plaintext_is_refused_unless_the_operator_opted_in` pins against a PUBLIC address. There is no
   configuration path to `allow_plaintext` for this plane at all — `A2aPlane` builds
   `FetchPolicy::default()` and only `allow_private` is lowered per registration by
   `fetch_policy_for`, so no operator, and no rig, can turn this off. **A topology change cannot
   reach this refusal.**
2. ~~**The caller's credential is never stored, so it can never be echoed.**~~ **BUILT — blocker
   removed.** `PUSH-DELIVER-001` asserts the delivery carries `Authorization: <scheme>
   <credentials>` from the config's `authentication` member, and busbar used to drop that member at
   registration: the task row held one `push_callback` STRING, the create/read verbs echoed
   `{id, url}`, and `pushdeliver::DELIVERY_HEADERS` was `content-type` and nothing else. The
   config's `authentication` is now read on BOTH registration paths (the inline config on a
   submission and `CreateTaskPushNotificationConfig`), held by `pushdeliver`, and presented on the
   delivery. It is not echoed on a read verb and it is not written to the durable row — see
   `a2a/pushdeliver.rs` for why an in-memory credential is the safe direction to degrade in.
3. ~~**The payload is a bare `Task`, and the requirement wants a `StreamResponse`.**~~ **BUILT —
   blocker removed.** The verdict that established it, from the TCK's own validator run over
   `pushdeliver::notification_body`'s exact document:

   ```
   busbar body valid: False
     - $: 'contextId', 'id', 'kind', 'status' do not match any of the regexes:
          '^(artifact_update)$', '^(status_update)$'
   wrapped-in-task valid: True
   ```

   `Stream Response` is `additionalProperties: false` over `{task, message, statusUpdate,
   artifactUpdate}`, so the un-nested document was rejected and the same document nested under
   `"task"` validates. `notification_body` now emits the nested form.

**SO ONE BLOCKER REMAINS, AND IT IS THE SCHEME.** All three requirements still fail, and they fail
for blocker 1 alone: the suite's receiver is `http://` by literal and busbar refuses a plaintext
callback before it parses an address. Blockers 2 and 3 were real capability gaps rather than rig
defects, they are owed to every customer whose webhook IS https, and they were built for that
reason rather than for this number — which is why fixing them moved this number not at all. That is
the expected outcome and is recorded so nobody reads the unchanged red as the fix not landing.

**WHAT IS NOT DONE ABOUT IT, DELIBERATELY.** Nothing here is made green by relaxing a control.
`a2a/pushnotify.rs` is byte-identical to the commit under test: no `allow_private` for webhooks, no
loopback exemption, no conformance-only flag, and the unconditional cloud-metadata refusal
untouched. The alternative — patching the pinned TCK so its receiver advertises `https` — would
change the instrument to suit the subject, which is the failure mode this whole directory exists to
refuse.

**WHAT WOULD RETIRE THIS WAIVER**, in the order the checks fire:

1. An owner's decision on whether busbar accepts a plaintext webhook at all, and on what operator
   surface. It is a real question rather than a formality: the callback carries task ids and caller
   attribution, and the suite's own receiver is plaintext, so the suite cannot be satisfied by an
   implementation that refuses plaintext outright. **This is now the ONLY remaining blocker, and it
   is the one that is not busbar's to fix.**
2. ~~Storing the config's `authentication` alongside the URL, with the same guard applied, and
   sending it on delivery.~~ DONE.
3. ~~Wrapping the delivered document in the `StreamResponse` envelope.~~ DONE.
4. THEN the topology, which is real and is still needed: the receiver binds `0.0.0.0` already, so it
   is `--webhook-host` plus a rig where busbar sees a genuinely public address — busbar and the
   suite in two containers on a docker network whose subnet is outside every range
   `net_guard::ip_is_internal` refuses. The host's own addresses do not qualify and must not be
   argued into qualifying: `10.144.x` is RFC1918, `192.168.x` is RFC1918, the TEST-NET blocks are
   `is_documentation()`, and `100.64/10` is CGNAT — the guard refuses all of them, correctly.

Until then the release ships with these three RED and says so.

---

## `CARD-EXT-001` — waived 2026-08-12, FIXED 2026-08-15

**FIXED 2026-08-15.** The waiver below is retained as the record of why this row was once red; it
no longer waives anything. What settled it was reading the schema divergence the right way round:
SPEC 1.4 makes `a2a.proto` the NORMATIVE definition of every wire structure and the prose/sample
card informative, and the strict validator behind this requirement is generated from the proto. Of
the three members the validator rejected, two had already been fixed on the proto's side of the
divergence (`protocolVersion` removed, `securityRequirements` spelled as the proto spells it) —
the third, `capabilities.stateTransitionHistory`, was a member the 1.0 `AgentCapabilities` simply
does not define: no ProtoJSON reader can parse it, so publishing it served nobody. busbar's card
now carries only proto-defined capability members
(`crates/busbar/src/a2a/serve.rs::self_card_document`, pinned by
`every_published_capability_is_one_the_normative_proto_defines`), and the behaviour the old member
claimed is unchanged — task history is served per request under `historyLength`, which needs no
flag. Verified 2026-08-15: `CARD-EXT-001` PASS on all three transports
(`run-tck.sh` subject leg), and the served card passes the suite's own strict `Agent Card` schema.
The sample-card divergence recorded below remains upstream's to resolve; busbar no longer sits on
the losing side of it.

### The original waiver record (historical)

**WHAT CHANGED, AND WHY THE NUMBER MOVED THE WAY IT DID.** busbar now implements
`GetExtendedAgentCard` / `agent/getAuthenticatedExtendedCard` and its card declares
`capabilities.extendedAgentCard: true`. That flip moves two MUSTs, and both movements are
consequences of the capability existing rather than of anything being broken:

```
                  before                       after
CORE-CAP-003      PASS                         SKIPPED
CARD-EXT-001      SKIPPED                      FAILED
MUST row          73 passed, 25 failed, 16     72 passed, 26 failed, 16
```

`CORE-CAP-003` is *"Extended agent card returns error when not supported"*. It skips itself the
moment the capability IS supported, so it is passable only by not having the verb. It was passing
because busbar did not have it.

**METHOD FOR `CARD-EXT-001`.** `scripts/a2a-subject/boot.sh --tck` against a busbar built from this
commit, TCK pinned at `5996b79f9cefa6fc390980e383e358a66fb9e49e`. The first run named two members:

```
✗ CARD-EXT-001 (jsonrpc): $: 'protocolVersion', 'security' do not match any of the regexes:
  '^(default_input_modes)$', '^(default_output_modes)$', '^(documentation_url)$',
  '^(icon_url)$', '^(security_requirements)$', '^(security_schemes)$',
  '^(supported_interfaces)$'
```

`protocolVersion` was a REAL DEFECT and is FIXED. The top-level member said `0.3.0`: a patch number
the specification says a card must not carry, naming one version for an endpoint that admits two.
The 1.0 `AgentCard` has no such member at all — the version belongs to each `AgentInterface`, and
busbar now publishes one per interface per version it admits. After the fix the same requirement
fails on the remaining member alone:

```
✗ CARD-EXT-001 (jsonrpc): $: 'security' does not match any of the regexes:
  '^(default_input_modes)$', '^(default_output_modes)$', '^(documentation_url)$',
  '^(icon_url)$', '^(security_requirements)$', '^(security_schemes)$',
  '^(supported_interfaces)$'
```

(The suite reports the first error only. Driving the same validator directly shows two more behind
it: `capabilities.stateTransitionHistory`, and the shape of `securitySchemes` — busbar publishes the
JSON form `{"type": "http", "scheme": "bearer"}` where the generated schema expects the ProtoJSON
`oneof` wrapper `{"httpAuthSecurityScheme": {…}}`.)

**REASON THE REST IS WAIVED: the requirement validates the returned card against a strict ProtoJSON
schema that the SPECIFICATION'S OWN SAMPLE AGENT CARD does not satisfy.** Run the suite's own
validator over the card printed in specification section 8.5, unmodified:

```
the specification's own section 8.5 sample card, strict: False
   - $: 'security' does not match any of the regexes: … '^(security_requirements)$' …
   - $.capabilities: 'stateTransitionHistory' does not match any of the regexes:
        '^(extended_agent_card)$', '^(push_notifications)$'
```

Those are exactly the two members busbar's card carries, and busbar carries them because that sample
is where a card's JSON shape is documented: it spells the member `security` and it declares
`stateTransitionHistory`. The generated schema spells one `security_requirements` and does not know
the other. Only the extended-card requirement validates strictly — `CARD-STRUCT-001` validates the
same document with `allow_additional=True` and passes — so the divergence is visible on exactly one
row.

**WHAT IS NOT DONE ABOUT IT, DELIBERATELY.** busbar does not reshape the card it publishes to satisfy
a schema the specification's own example contradicts. Doing so would change the document every A2A
client reads to learn how to authenticate to busbar, on the authority of a generated artefact that
disagrees with the prose and the sample it was generated alongside. That is changing the product to
suit one instrument's reading, and the reading is not the one clients implement.

**WHAT WOULD RETIRE THIS WAIVER.** Upstream resolving the divergence — either the schema accepting
`security` and `stateTransitionHistory`, or the specification's sample card and prose moving to
`securityRequirements` and dropping `stateTransitionHistory`. When it resolves, busbar follows the
resolution, in whichever direction it goes.
---

## `GRPC-ERR-001` — recorded 2026-08-12, FIXED 2026-08-15

**FIXED 2026-08-15.** The dependency decision recorded below was taken: the canonical
`google.rpc.{Status,ErrorInfo}` types come from `tonic-types` — the tonic project's own crate,
whose entire dependency set (`prost`, `prost-types`, `tonic`) was already in the lock, so the new
supply-chain surface is that one crate and nothing behind it. A refused gRPC call now carries the
protobuf `google.rpc.Status` in the `grpc-status-details-bin` trailer with a `google.rpc.ErrorInfo`
detail — TRANSCRIBED from the same ProtoJSON `ErrorInfo` the JSON-RPC binding already carries in
`error.data` (one section 5.4 table, one fact, re-encoded; a relayed backend's `metadata` survives
into the trailer), never re-derived beside the service
(`crates/busbar/src/a2a/grpc.rs::error_info_of`, pinned by
`an_a2a_refusal_carries_error_info_in_the_status_details_trailer` and its no-invented-reason
control). Verified 2026-08-15: `GRPC-ERR-001` PASS (`run-tck.sh` subject leg).

### The original record (historical)

**METHOD.** `scripts/a2a-subject/boot.sh --tck` against a busbar built from this commit, TCK pinned
at `5996b79f9cefa6fc390980e383e358a66fb9e49e`, on the run that first armed the gRPC binding. MUST
row from the suite's own stdout:

```
│ MUST        │     74 │     30 │      10 │   114 │
```

Per-transport, from the same report: `grpc: 62/72 (4 skipped)`, where it read `grpc: 0/72 (72
skipped)` before this binding existed. `GRPC-ERR-001` is the ONLY requirement failing on the gRPC
transport and no other, verbatim:

```
✗ GRPC-ERR-001 (grpc): gRPC error does not contain google.rpc.ErrorInfo in trailing metadata
  (grpc-status-details-bin)
```

**WHAT IT ASKS FOR.** A refused gRPC call must carry a `google.rpc.Status` in the
`grpc-status-details-bin` trailer, holding a `google.rpc.ErrorInfo` whose `reason` names the A2A
error. busbar answers the correct `grpc-status` and `grpc-message` for every error in the
specification's table — `GRPC-ERR-002` and `GRPC-ERR-003` both pass — and carries the same
`ErrorInfo` on the JSON-RPC binding, in `error.data`. What is missing is only the protobuf-encoded
copy of it in the trailer.

**WHY IT IS NOT CLOSED IN THIS UNIT.** The trailer's payload is `google.rpc.Status` and
`google.rpc.ErrorInfo`, and neither is in this tree: the vendored `a2a.proto` brings `google.api`
and nothing else. Closing it means either a new dependency carrying the canonical Google protos, or
hand-encoding two protobuf messages beside the service — and hand-writing a wire fact is exactly
what adopting the publisher's own generated types was meant to end. Which of those to take is a
dependency decision rather than a coding one.

**WHAT IS NOT DONE ABOUT IT, DELIBERATELY.** The requirement is not marked, skipped or excluded. It
runs, it fails, it is counted in the MUST row above, and it is the reason that row is not two
higher.

**THE TWO MUST ROWS ABOVE WERE MEASURED ON TWO BRANCHES, BEFORE THEY MET.** The `CARD-EXT-001` row
(`72 passed, 26 failed`) was read on a busbar serving JSON-RPC and HTTP+JSON; the `GRPC-ERR-001` row
(`74 / 30 / 10`) was read on one serving JSON-RPC and gRPC. Neither is the merged tree's row, and
neither is restated here as though it were: what each records is the requirement it was written
about and the evidence for that requirement, which the merge does not change. The merged row is
whatever the next full `--tck` run prints.
