# a2aht: an independent A2A conformance battery

A third-party conformance and differential test harness for the Agent2Agent
(A2A) protocol, written from the published specification alone.

Spec basis: `github.com/a2aproject/A2A` tag **v1.0.1**, with
`specification/a2a.proto` treated as normative per SPEC section 1.4.

The harness knows nothing about any particular implementation. There are no
per-implementation branches in it and there must never be any. If a subject
needs one to be testable, that is a finding about the specification being
underspecified and it belongs in the report.

Full write-up, including the control selection, the verbatim control result,
the spec ambiguities found, and what could not be determined:
`../../design/a2a-independent-test-battery.md`

## Requirements

Python 3.9 or newer. Standard library only. The `cryptography` package is used
if present, for agent card JWS verification; without it those tests report the
signature as unverifiable rather than as verified.

## Run it against any A2A agent

    python -m a2aht run --endpoint http://127.0.0.1:8080

Or have the harness start and stop the agent itself:

    python -m a2aht run --launch "my-agent serve --port 8080" --port 8080

To also exercise the agent's CLIENT role, give a command that makes it
delegate outward. `{url}` is replaced with a fake peer the harness controls:

    python -m a2aht run --endpoint http://127.0.0.1:8080 \
      --client-drive "my-agent delegate --to {url}"

Without `--client-drive` the client-role tests report NOT_CONFIGURED and the
run is red. They never skip quietly.

## Differential against the control

    ./scripts/install-control.sh go

    python -m a2aht run \
      --launch "$HOME/.a2aht/bin/a2a serve --echo --port 9099 --quiet" \
      --port 9099 --label control --json control.json --allow-red

    python -m a2aht run --endpoint http://127.0.0.1:8080 \
      --label subject --json subject.json --allow-red

    python -m a2aht diff --control control.json --subject subject.json

The differential separates two things that must never be conflated:

- **DEFECTS**: the subject violated a spec MUST. A defect is a defect whatever
  the control does. The control is never used to excuse one.
- **DIVERGENCES**: subject and control differ where the spec permits variation.
  Reported with both values and the governing clause, for a human. Never a
  failure.

## Tiers

    --tier every-commit    fast, hermetic, no optional capabilities
    --tier pull-request    the default; full conformance and adversarial
    --tier pre-release     adds slow, large-payload and timing-sensitive work

## Other commands

    python -m a2aht list --clauses      the battery, with defect lines
    python -m a2aht baseline --report R --baseline B

`baseline` asserts a control run is identical to its recorded baseline. This
is what CI uses: it catches both a harness change and a silent control upgrade.

## Layout

    a2aht/spec.py               normative constants, every one cited
    a2aht/model.py              assert_must vs observe, the test registry
    a2aht/validate.py           structural validators
    a2aht/jcs.py                RFC 8785 canonicalisation, JWS verification
    a2aht/transport.py          HTTP, SSE, and raw-socket misbehaviour
    a2aht/target.py             the parameterised target
    a2aht/fakes.py              honest and hostile fake peers, webhook sink
    a2aht/tests_card.py         agent card and discovery
    a2aht/tests_core.py         operations and task lifecycle
    a2aht/tests_adversarial.py  malformed input
    a2aht/tests_hostile.py      well-formed but malicious peers
    a2aht/tests_client.py       the target's client role, and the seam
    a2aht/runner.py             battery, reports, differential
    baselines/                  pinned control results
    scripts/install-control.sh  pins the control versions

CI: `.github/workflows/a2a-conformance.yml`
