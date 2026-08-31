# Supplementary A2A coverage — busbar-authored, reported separately, never added

**This is not the A2A TCK, and nothing in it may ever be counted as a TCK result.**

The official suite in `../a2a-tck` pins `a2aproject/a2a-tck` at
`5996b79f9cefa6fc390980e383e358a66fb9e49e`. In that suite, **21 of the 114 MUST requirements have
no test anywhere**: their `test_ids` are empty, their `transports` map is empty, and a `grep -rl`
over the suite's own `tests/` tree returns nothing for them. The summary counts them among the
failures; the JSON report calls them `NOT TESTED`. That is not a busbar property — the same
families appear against the two committed `a2a-go` control baselines, which are a different
implementation by different authors.

So the arithmetic ceiling on that pin is **93, not 114**, and no amount of work on busbar can move
the other 21. This directory covers all 21: seventeen are decided, one fails, one is partial and
two are untestable from outside with the mechanism stated.

**A subject run usually reports 22 or 23 `NOT TESTED`, and the extra one or two are NOT this gap.**
`JSONRPC-SVC-002` and `HTTP_JSON-SVC-002` DO have tests in the pinned suite; those tests time out
(`httpcore.ReadTimeout` on a fresh connection carrying an `A2A-Extensions` header), the exception
escapes before `assert_and_record` runs, and nothing is recorded — so they land in the report with
empty `test_ids`, indistinguishable from a requirement with no test at all. `VER-SERVER-003` does
the same intermittently under load. **A hang and a coverage gap are not the same finding**, and the
official report cannot tell them apart; the 21 here were established by grepping the suite's own
`tests/` tree, not by reading the report.

## The rule that governs everything here

**A busbar-authored pass is weaker evidence than a third-party pass, and the two numbers are never
added.** The official number comes from the specification publisher's own oracle. This number comes
from the implementer grading their own implementation. Presenting them as one figure would launder
the weaker into the stronger and make the whole exercise worthless. Every report this suite emits
carries that warning above its own counts, and records it in the JSON under
`not_an_official_number`.

## The three rules that keep it from being a mirror

A test written by reading busbar's source, run against busbar, that passes, has established
nothing: it is equally consistent with the test being right and with the test asserting whatever
busbar happens to do. Three things guard against that.

**1. Every check is written from the specification text, never from busbar's implementation.**
`a2asup/spec.py` carries the normative sentence for each requirement, transcribed verbatim from
`specification/specification.md` at the pinned commit. Where a sentence admits more than one
reading, the `reading` field states which one is encoded **and why** — see `AUTH-SERVER-002`, where
the weak reading makes the MUST unfailable, and `AUTH-SCOPE-002`, where the authorization model is
agent-defined and only one consequence holds under all of them.

**2. Every check is run against third-party controls, and the control's result is published.**
`run-supplement.sh` drives the same checks against `a2a-go` v2.4.0 on two bindings and against the
A2A project's own Python SDK. A check that passes busbar and passes a control may be real or may be
vacuous. A check that **discriminates** — passes one and fails the other, for a stated reason — has
proven it has a failure mode.

**3. There is no skip.** The verdicts are `PASS`, `FAIL`, `PARTIAL`, `UNTESTABLE`,
`NOT_APPLICABLE` and `ERROR`. A check that raises becomes `ERROR` and is counted as not-passed; a
probe inside a check that raises is counted as *not refused*, the conservative direction. An
earlier draft of `AUTH-SERVER-002` appended probe exceptions to the evidence and continued, and
reported `PASS` having driven nothing — exactly the false green this suite exists to refuse. That
is why the rule is written down.

`UNTESTABLE` is a real finding, not an absence of one. Two requirements are reported that way with
the mechanism stated, and an honest "cannot be decided from outside, and here is why" is worth more
than an assertion that asserts nothing.

## Why here, and not in the pinned suite or upstream

Three places were possible.

**Editing the pinned TCK in place** is wrong. `run-tck.sh` fetches that commit over the network and
**refuses to run** if the checkout's hash is not the pin. A local edit is either overwritten or
turns the pin into a lie, and a suite you can edit is not an oracle.

**A sibling directory**, which is what this is. It runs the same requirement IDs against the same
subject, is labelled busbar-authored everywhere it prints, and is reported in a column of its own.
It borrows exactly one thing from the pinned checkout — the interpreter and the specification's own
generated protobuf stubs — so the gRPC binding is driven through the publisher's types rather than
a hand-rolled encoder, and so the pin is verified in exactly one place.

**Upstream** is where these belong if they are good, and the suite's own backlog has three open
`coverage-gap` tasks for precisely these families. See "Upstreaming" below.

## What runs

    scripts/a2a-subject/boot.sh --supplement     busbar, booted from this commit, two principals
    testing/a2a-supplement/run-supplement.sh control-jsonrpc      a2a-go v2.4.0, JSON-RPC
    testing/a2a-supplement/run-supplement.sh control-http-json    a2a-go v2.4.0, HTTP+JSON
    testing/a2a-supplement/run-supplement.sh control-scenario     a2a-python, direct

The busbar leg lives in the subject rig rather than here because it needs things a bare URL cannot
supply: a booted busbar, **two distinct authenticated principals** (without which the scoping
requirements cannot be decided at all — with one identity, an implementation that scopes perfectly
and one that does not scope at all are observationally identical), an out-of-band copy of the
card-signing public key, and a recorder on the upstream leg for the one requirement that is about
the **client** role.

## Upstreaming

Feasible, and worth doing. The checks are written against the specification, not against busbar;
nothing in `a2asup/` mentions busbar's internals; the requirement IDs are the TCK's own; and the
gRPC leg already speaks the specification's generated stubs. Porting means rewriting each check as
a pytest module under `tests/compatibility/` using the suite's `compatibility_collector` and
`assert_and_record` idiom, which is mechanical.

Two things the TCK would have to grow first, and they are the reason these requirements are
untested there rather than an oversight:

- **A second credential.** The TCK's `run_tck.py` takes `--sut-host` and nothing else. The scoping
  requirements need two principals, and there is no surface to hand them over.
- **An upstream vantage point.** `VER-CLIENT-001` is a requirement on the *client* role and cannot
  be decided by probing a server's front door.

Both are additive CLI changes. The `AUTH-*`, `BIND-EQUIV-*` and `CARD-SIGN-*` families that need
neither could be contributed as-is.

## Proving the checks bite where no control can

`run-supplement.sh`'s controls establish a failure mode for the `AUTH-*` and `VER-SERVER-*`
families. `a2a-go` v2.4.0 fails `AUTH-SERVER-002`, `AUTH-SCOPE-001/002`, `AUTH-INTASK-002/003` and
`VER-SERVER-001` where busbar passes, and `a2a-python` **passes** `AUTH-INTASK-002/003` and
`VER-SERVER-001` — a third-party implementation passing a check is as important as one failing it,
because a check that only ever passes the subject that shipped with it is a check nobody has seen
work on anything else.

They establish **nothing** for three families, and that is stated rather than glossed:

| Family | Why no control decides it |
|---|---|
| `BIND-EQUIV-*` | every available control serves exactly **one** binding, so SPEC 5.1 is vacuous against it by its own first clause |
| `CARD-SIGN-*` | no available control signs its agent card; signing is `MAY` in SPEC 8.4 and almost nobody does it |
| `VER-CLIENT-001` | no control is a gateway, so none originates an upstream A2A request to observe |

For those, `selftest.py` supplies the missing evidence the only other way there is: it builds a
subject that is deliberately wrong in exactly the way each requirement forbids, runs the real check
against it, and **fails if the check passes**. Every mutation is paired with a positive control, so
a check that simply fails everything cannot pass the selftest either. Run it the way
`run-supplement.sh` runs the suite; a red there means a check is asleep and no verdict from the
suite should be believed until it is fixed.

## What it found

**One red, and it is not a conformance nicety.** `AUTH-SCOPE-003` fails: a second authenticated
principal can `Get Task` a task belonging to the first and receives `200` with the task, while an
id that exists for nobody is answered `-32001`/`404`. `AUTH-SCOPE-002` **passes** on the same run —
`List Tasks` *is* scoped — so the deployment has a per-principal boundary that the listing path
applies and the direct-read path does not. Reproduced on four consecutive boots on fresh ports.
Whether the intended boundary is the calling key or the fronted-agent registration is an owner's
question; either way the two operations cannot both be right about who may see a given task. **Not
fixed here** — an instrument that repairs what it measures stops being one.

`CARD-SIGN-003` passes its MUST (`alg` and `kid` both present) and the SHOULD is reported beside it,
not folded in: the protected header carries no `typ`, which SPEC 8.4.2 says SHOULD be `"JOSE"`.

## What this does not cover

Of the 23 untested MUSTs, this suite decides what can be decided from outside and says so plainly
about the rest. `AUTH-TLS-001` and the TLS half of `GRPC-SVC-003` are properties of a *deployment*
rather than of a build; `AUTH-INTASK-004` is about a channel that is by definition not the A2A
connection. Each is reported `UNTESTABLE` or `PARTIAL` with the mechanism, and never as a pass.
