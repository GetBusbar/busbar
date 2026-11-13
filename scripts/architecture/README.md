# Protected native admission

The project CI setting selects `ci/architecture-pipeline.yml@GetBusbar/busbar:<SHA>`.
Use a full immutable architecture-owner-approved revision. The bootstrap derives that
revision from GitLab's `CI_CONFIG_REF_URI`, checks it out independently, and executes
its checker, compiler witnesses and native command list against the candidate.
Changing a candidate's YAML, policy or checker does not change the running policy.

The owner runs `admission.py`; its Git credential must never be installed in a runner
or candidate job. The script requires explicit server, policy revision, local matching
policy bytes and controlled merge-user IDs. `inspect` is read-only. `apply` installs
the external CI setting, fast-forward merges, required successful pipelines, disabled
pipeline-variable overrides and no direct/job-token/force pushes. Existing stricter
QA/main merge permissions stay unchanged. Creating a missing QA/main protection
requires an explicit `--stage-owner-id`; it never grants the dev operator promotion access. `merge` accepts only a same-project dev MR
with the current successful native job and an exact source/target/host/SDK/policy receipt.
For core that is its DEV tier: the MR pipeline's `core-build` receipt (fmt, deny/vet and
the plain certified release build with its sha256), the lint-only `core-clippy` receipt, the
`core-test` receipt (root workspace doctests and nextest run, every step passing) and
the `core-conformance` receipt that judged those same bytes; native qualification,
debug-assertion conformance and security are core's QA tier.
Every matching project and group rule is checked because permissions are additive.
Unreadable group rules, permissive wildcards or unavailable settings prevent admission.
The server also rejects a merge when the target has advanced beyond the candidate.

An eligible existing runner must have tag `busbar-native-admission` and access to both
public-project and private-enterprise MR jobs. Use an isolated native Linux executor
with Rust 1.98.0, Cargo nextest/deny/vet, Python 3.11+ with PyYAML/jsonschema, Node, a C compiler with
ThreadSanitizer, Git, jq, and Docker for the existing digest-pinned service fixtures.
Set `BUSBAR_NATIVE_SCRATCH` to an operator-owned scratch root outside project checkouts.
No cloud, deployment or merge credential belongs in these jobs. The short-lived job
token fetches trusted/private sources; core must allow inbound job-token access from
the participating projects/groups. An eligible runner is an operator dependency,
not permission to provision a machine or borrow an unrelated deployment runner.

SDK source and assembled-product revisions are separate identities. For an ABI cutover,
the owner sets `BUSBAR_ADMISSION_CORE_REVISION` to the exact assembled cohort candidate
in project settings, unprotected so merge request pipelines receive it (the pin is not a
secret; every internal ref is trusted). Ordinary pipelines cannot override it. Once admitted, remove the
cohort override: the job resolves canonical dev once and records its actual revision.
The selected host's SDK pin must match the plugin's `.busbar-ref`. Native conformance
records the tested host commit, rather than mislabeling the SDK commit as a binary.
Admission resolves the current owner-selected host and its SDK vector again; a passing
receipt for an older host or SDK cannot admit the candidate.
Before compilation, the trusted source collector fetches the exact public Git inputs
from canonical repositories into a task-local cache. Cargo receives credential-free
local URL mappings while source identities and lockfiles stay unchanged. This permits
qualification before public stage mirrors advance, without publishing candidate branches.

`native.py` refuses execution outside GitLab. It runs the existing required full suites
and assembled-product checks there; local development uses fmt/clippy/build and targeted
regressions. Missing services, native libraries, inputs, tools or receipts fail the job.
Job artifacts retain source/SDK/host/policy identities, commands, actual exit codes,
dependency/lock hashes and binary/library hashes. Each command retains hashed logs;
nextest steps also retain their actual JUnit reports. Existing plugin conformance suites retain
source-bound invocation and verdict files for the website collector. Fixtures and job scratch are removed
after evidence export. Enterprise artifacts remain member-only in private projects.

Successful core and public-plugin dev jobs trigger the existing marketing dev pipeline.
Core binds `WEBSITE_CORE_REVISION` to the exact assembled commit; plugin events carry
their own source identity and resolve the assembled dev host independently. The website independently checks
branch freshness and publishes the current results at `/certifications/`. A failed,
missing or stale qualification cannot trigger a green publication. Successful native
CI evidence does not create a signed certification or promote code to QA/main.

Run the finite tooling regressions with `python3 -m unittest discover -s
scripts/architecture -p 'test_*.py'`. Production policy/API changes require the owner
to review and select a new immutable policy revision; candidate authors cannot expand
their own dependency role, public surface or service authority.
