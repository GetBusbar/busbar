# TCK requirements busbar does not meet, and why — recorded, not hidden

Every entry here names a requirement the official suite reports as FAILED against busbar, the method
by which that was established, the reason it is not being made to pass, and the date. A requirement
that is failing for a reason nobody wrote down is indistinguishable from one nobody noticed, which
is the whole point of this file.

Read alongside `scripts/a2a-subject/boot.sh` (which produces the number) and `run-tck.sh` (which
runs the suite). **Nothing here silences a test.** Every waived requirement still runs, still fails,
and is still counted in the MUST row.

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
2. **The caller's credential is never stored, so it can never be echoed.** `PUSH-DELIVER-001`
   asserts the delivery carries `Authorization: <scheme> <credentials>` from the config's
   `authentication` member. busbar's task row holds one `push_callback` STRING
   (`taskstore::set_push_callback`), the create/read verbs echo `{id, url}` only, and
   `pushdeliver::DELIVERY_HEADERS` is `content-type` and nothing else. The credential is dropped at
   registration.
3. **The payload is a bare `Task`, and the requirement wants a `StreamResponse`.** Checked by
   running the TCK's own validator over `pushdeliver::notification_body`'s exact document:

   ```
   busbar body valid: False
     - $: 'contextId', 'id', 'kind', 'status' do not match any of the regexes:
          '^(artifact_update)$', '^(status_update)$'
   wrapped-in-task valid: True
   ```

   `Stream Response` is `additionalProperties: false` over `{task, message, statusUpdate,
   artifactUpdate}`; the same task document nested under `"task"` validates.

So only `PUSH-DELIVER-002` would pass if blocker 1 were removed; 001 and 003 are implementation
gaps, not rig defects.

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
   implementation that refuses plaintext outright.
2. Storing the config's `authentication` alongside the URL, with the same guard applied, and sending
   it on delivery.
3. Wrapping the delivered document in the `StreamResponse` envelope.
4. THEN the topology, which is real and is still needed: the receiver binds `0.0.0.0` already, so it
   is `--webhook-host` plus a rig where busbar sees a genuinely public address — busbar and the
   suite in two containers on a docker network whose subnet is outside every range
   `net_guard::ip_is_internal` refuses. The host's own addresses do not qualify and must not be
   argued into qualifying: `10.144.x` is RFC1918, `192.168.x` is RFC1918, the TEST-NET blocks are
   `is_documentation()`, and `100.64/10` is CGNAT — the guard refuses all of them, correctly.

Until then the release ships with these three RED and says so.
