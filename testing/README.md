# Independent protocol batteries

Third-party conformance instruments pointed at the A2A protocol, and a governance probe that is
deliberately not one of them. `.github/workflows/a2a-conformance.yml` runs all of it on every push
and every pull request.

| Directory | What it is | Gates on |
|---|---|---|
| `a2a-harness/` | An independent A2A battery, written from the published specification alone. 85 tests, including adversarial and hostile-peer coverage. | A pinned per-test verdict against two third-party controls |
| `a2a-tck/` | A wrapper around `a2aproject/a2a-tck`, the specification publisher's own suite: all three transports including gRPC, 36 test modules. Fetched at a pinned commit, never vendored. | A pinned per-requirement verdict against a third-party control |
| `a2a-supplement/` | **Busbar-authored** coverage of the 23 MUST requirements the pinned TCK declares and has no test for. Reported in a column of its own. | Its own MUST result, never merged into the TCK's |
| `a2a-governance/` | Budgets, quarantine, trust lifecycle, audit. **Product policy, not protocol.** | Nothing. It reports observations |

## The supplement is a THIRD kind of evidence, and it is the weakest

`a2a-supplement/` exists because **23 of the pinned TCK's 114 MUSTs have no test anywhere in it** —
empty `test_ids`, empty `transports`, and nothing in its own `tests/` tree. The same gap shows
against the two committed `a2a-go` control baselines, so it is a property of the suite and not of
busbar. The arithmetic ceiling on that pin is 91, not 114.

**Its number and the TCK's are never added.** The TCK is the specification publisher's oracle; the
supplement is the implementer grading their own implementation, which is strictly weaker evidence.
Adding them would launder the weaker into the stronger. Every report the supplement emits says so
above its own counts and records it in the JSON. Read `a2a-supplement/README.md` before quoting
anything from it.

## Two instruments, on purpose

They are not redundant and neither replaces the other. The independent battery is a clean-room
reading of the specification, which is what lets it find things nobody thought to test — it caught
an unauthenticated remote panic in a reference implementation from a 60-byte JSON document. The
official TCK is the publisher's own oracle, and it covers transports the battery does not drive.
Writing our own gRPC driver instead of wiring the TCK would have been several days spent
duplicating a suite somebody else keeps current.

Both are held to a **pinned verdict against a pinned third-party control**, not to "green". Neither
suite is green against any implementation that exists, and that is fine: the thing a gate has to
catch is a CHANGE, and a suite whose result is unchanging catches one perfectly.

## Governance is a separate tier and must stay one

A conformance pass says the target speaks A2A correctly. It says nothing about whether the target is
safe to point at the internet. **A perfectly conformant agent that ignores every budget and never
quarantines anything scores 100% on conformance.**

So `a2a-governance/` is a different tool that imports `a2a-harness` as a library, and the harness
**raises** if a governance test is ever registered inside it — the wall is code, not convention.
`harness-selftest.py` proves the raise still happens by making it happen.

## What runs, and what is allowed to skip

**The control legs run always.** A battery that cannot judge a known-good peer cannot be trusted to
judge ours, so every run re-establishes that both instruments still produce their pinned verdicts
against `a2a-go` v2.4.0 and `a2a-python` 1.1.2.

**The subject leg skips until armed** by one repository variable naming busbar's A2A endpoint:

```
gh variable set BUSBAR_A2A_ENDPOINT -R GetBusbar/busbar -b 'http://127.0.0.1:8080'
```

It does not fail while unarmed. busbar does not serve A2A yet, and a job that is red today for a
reason that is not a defect is how red stops meaning defect.

**Everything else that does not reach `success` is red, including a skip.** The `verdict` job checks
each leg's result by name; a control leg that was skipped or cancelled fails there. The subject leg
publishes its arm state as a job output rather than relying on its result, because a job whose steps
all skip still reports `success` — which is the exact false green the rest of this is built to
refuse.

## Why these live here

A conformance battery is a statement about busbar, so it belongs where busbar is built and where a
red blocks the release it is about. **Independence is a property of authorship, not of location**:
these were written without reading busbar's implementation, and the guard that keeps product
knowledge out of the harness is enforced in code.

The earlier arrangement put this CI in a repository whose host has no runners registered and no
route from GitHub-hosted ones. Eight jobs failed permanently and the only two that went green had
executed nothing — a standing red nobody could fix, which teaches everyone to ignore the signal.
That is the same defect these batteries exist to catch, one level up.

busbar is public, so per the org rule (public → GitHub-hosted, private → `busbar-selfhosted`) every
job here runs on `ubuntu-latest` at no cost. **There is no secret anywhere in the workflow**, which
is what makes "the control legs run always" achievable rather than aspirational.

## Running any of it locally

```sh
# the machinery, before believing any verdict it produces
python3 testing/a2a-harness/scripts/harness-selftest.py
python3 testing/a2a-tck/check-baseline-selftest.py

# the independent battery against the pinned control
testing/a2a-harness/scripts/install-control.sh go
cd testing/a2a-harness && python3 -m a2aht run \
  --launch "$HOME/.a2aht/bin/a2a serve --echo --port 9099 --quiet" --port 9099 \
  --json /tmp/control.json --allow-red
python3 -m a2aht baseline --report /tmp/control.json \
  --baseline baselines/control-a2a-go-rest.json

# the official TCK against the pinned control
testing/a2a-tck/run-tck.sh control-http-json

# six states the gate must tell apart
testing/a2a-harness/scripts/swap-proof.sh
```

Note the timezone. The control legs run with `TZ` fixed to a non-UTC zone, because `a2a-go` v2.4.0
serialises timestamps in the host's local zone and the resulting spec violation is **invisible on a
UTC host** — which every CI runner is. `tz-is-load-bearing.sh` re-runs the control under `TZ=UTC` and
requires the pinned baseline to break, so that setting cannot quietly become decoration.

Licences of everything fetched at run time: `a2a-tck/LICENSING.md`.
