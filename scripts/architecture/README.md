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
QA/main merge permissions stay unchanged. `merge` accepts only a same-project dev MR
with the current successful native job and an exact source/target/policy receipt.
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
in project settings. Ordinary pipelines cannot override it. Once admitted, remove the
cohort override: the job resolves canonical dev once and records its actual revision.
The selected host's SDK pin must match the plugin's `.busbar-ref`. Native conformance
records the tested host commit, rather than mislabeling the SDK commit as a binary.

`native.py` refuses execution outside GitLab. It runs the existing required full suites
and assembled-product checks there; local development uses fmt/clippy/build and targeted
regressions. Missing services, native libraries, inputs, tools or receipts fail the job.
Job artifacts retain source/SDK/host/policy identities, commands, actual exit codes,
dependency/lock hashes and binary/library hashes. Fixtures and job scratch are removed
after evidence export. Enterprise artifacts remain member-only in private projects.

A successful assembled-product dev job triggers the existing marketing dev pipeline,
binding `WEBSITE_CORE_REVISION` to that exact commit. The website independently checks
branch freshness and publishes the current results at `/certifications/`. A failed,
missing or stale qualification cannot trigger a green publication. Successful native
CI evidence does not create a signed certification or promote code to QA/main.

Run the finite tooling regressions with `python3 -m unittest discover -s
scripts/architecture -p 'test_*.py'`. Production policy/API changes require the owner
to review and select a new immutable policy revision; candidate authors cannot expand
their own dependency role, public surface or service authority.
