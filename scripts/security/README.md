# Release security checks

`security-scans` is a mandatory, separate GitLab job selected by the immutable
external CI policy. Its receipt binds source, Git tree, source-file map, policy,
pipeline/job IDs, scanner image digests and vulnerability database digest/time.
The admission controller refuses missing, stale, optional or unsuccessful scans.
There is no `|| true`, candidate suppression policy or fallback to an unpinned tool.
Controlled direct dev pushes remain a separate owner capability, not an MR gate.

The trusted scanner exports committed blobs without Git export filters or attributes;
it never executes candidate build/package scripts. Symlinks are scanned as their
target text rather than followed. Submodules refuse pending separate qualification.
Only the source-free database-download container has network access. Source scans
use nonroot, read-only containers with no network, capabilities, host credentials,
Docker socket, writable policy or evidence mount. Reports cross stdout to the
controller, which checks both exit status and report findings/errors. Raw reports
and stderr are not retained because they may contain secrets or source excerpts;
receipts retain counts and hashes. Temporary raw files are unlinked on close.

Coverage:

- Trivy: current-tree secrets with built-in rules; HIGH/CRITICAL known dependency
  vulnerabilities, including unfixed vulnerabilities. History is not scanned.
  The database is independently downloaded, hashed and limited to 72 hours old.
- Semgrep CE: the explicit Python/Rust/C/JavaScript/TypeScript rules in
  `ci/security/semgrep.yaml`. This is bounded SAST, not full-code security proof.
  Reported parse/timeout errors refuse; the scanner is not a syntax validator.
  Semgrep may prefilter source irrelevant to its configured rules. Candidate
  ignore files and `nosem` comments cannot suppress findings. The rules are first-party, versioned with trusted policy;
  no remotely updated rules, account, Pro engine or SaaS upload are used.
- Existing native `cargo deny`/`cargo vet` remain required. Vet exemptions are not
  independent audits; review dependency policy changes as security-sensitive.
- Core publish gate G-S independently scans each CycloneDX SBOM and each declared OCI
  image platform before signing. It binds the candidate payload-file digest inventory
  into signed release evidence and refuses candidate mutation during the scans.
  G-3/G-4/G-8/G-10 and conformance retain inventory/closure/content responsibility.
  SBOM vulnerability scanning cannot detect an omitted dependency by itself.

Tool pins were resolved against the official Docker Hub manifest APIs on 2026-11-10:
Trivy 0.76.2 (Apache-2.0) and Semgrep CE 1.184.0 (LGPL-2.1). Tool images and their
dependencies are build infrastructure, not included in Busbar artifacts. No Snyk
license/token, Semgrep account, cloud credentials or signing key is required.
Registry access/rate limits can still prevent download; failure is not a pass.

## Deployment prerequisites and remaining boundary

The security job uses the existing `busbar-native-admission` instance executor.
Manager configuration was independently read back on 2026-11-10:
`capacity_per_instance=1`, `max_use_count=1`, `idle_count=0`, no external cache.
Each scanner job therefore gets its own fresh VM and Docker daemon; candidate
build processes never execute on that VM. Reusing the manager/template is safe
only while this one-use lifecycle remains enforced. Do not switch to a shared
shell worker or reuse a build VM under this tag. The native recipe supplies
Python 3.12, Docker socket access and `BUSBAR_NATIVE_SCRATCH=/var/lib/busbar-native`.
Keep source-fetch credentials outside scan containers and give the worker no
signing/cloud/promotion/merge credential. The deployed immutable policy produced mandatory successful security job 2370 in
core pipeline 1420 on 2026-11-10: source a261b97649f81fe13340a6543ff6226f4101e972,
policy c3e684c421696a0db3990b67cc2127d4d4872335. Its retained receipt has zero
findings and exit 0 for secrets, dependencies and SAST, with tool-image pins and
a database updated at 2026-11-10T13:03:09Z. This is exact-source scan evidence,
not qualification of later changes or final release artifacts; later vectors
must obtain their own mandatory receipts.

**Isolation evidence is runner-specific.** The 2026-11-10 rollout has an actual
successful Console `repository-gates` job (project 46, pipeline 1365, job 2237)
on runner 33: runsc, UID/GID `1000:1000`, unshadowed protected paths, measured
builder closure and automatic one-use VM/disk retirement. The pinned builder is
`source-builder@sha256:83a5fc11d5ad73acc645e600029767fa8d0ed42eb1b0ca4056f0d49c363ae594`.
A second observed `lifecycle-tools` job 2249 succeeded. The overall historical
pipeline failed; neither job qualifies the current core or all Console jobs.

Core native/conformance use runner 32, tagged `busbar-native-admission` and
`busbar-conformance`, with a separate instance executor. Its deployed `native.py` path executes
ordinary child processes; filtering their environment is not confinement.
The controller now rejects shell product-input output and imports only exact-key
JSON paths under candidate target/cache directories. Native receipts explicitly
record host-subprocess execution as isolated:false/release_eligible:false, and the
protected release producer requires independently pinned host-isolation evidence.
Same-user policy/receipt/cache access and the fixture Docker socket remain an
unresolved boundary in that deployed path. The new opt-in confinement backend
separates controller and candidate execution, protects harness/evidence mounts,
uses network-none nonroot containers, and brokers only fixed fixture endpoints.
Actual small existing-runtime checks cover denied host access and failure/timeout
disposal; they do not qualify the native toolchain, fixture roster or deployed
runner. Confined migration/conformance/generator paths still require engineering
and explicitly refuse unsupported execution. See
[the confinement contract](../architecture/CONFINEMENT.md). Runner 33's bridge/runsc setup cannot replace
this path merely by changing tags: core fixtures and TSan need qualified runtime
interfaces. The controller must freeze inputs, isolate candidate execution,
collect outputs as untrusted, and emit authoritative receipts outside the
candidate-writable namespace. No SLSA isolation claim follows from runner 32.

A live readback on 2026-11-10 found the manager still using the rollout's exact
startup digest and both runners paused. Runner 32 was subsequently resumed for
authorized CI availability, preserving its existing protected access and tags;
runner 33 was not changed. Resuming scheduling does not qualify native isolation.

The existing provenance packet remains **not activated**. Owner/producer inputs
still required: approved builder/predicate/source binding, controller evidence and
immutable artifact delivery; an approved exact artifact/bundle/receipt/certificate
identity/OIDC issuer tuple; protected QA/main routing. Scanner output does not
supply any of these. The G-9 release refusal remains intact. No production signing,
transparency-log writes, QA/main promotion or SLSA-level claims are authorized by
these changes. See `scripts/release/PROVENANCE.md`.

Source scan receipts retain one year in GitLab. Preserve final signed release
evidence and its input inventory for the supported release lifetime independently
of job expiration. The publish gate needs a local scanner Docker daemon and fresh
database in its trusted operator environment; it does not fall back if unavailable.

## Targeted validation

Run `python3 -m unittest discover -s scripts/security -p 'test_*.py'` with TMPDIR and
PYTHONPYCACHEPREFIX under the task scratch directory, plus the admission/bootstrap
tests touched by the integration. Real scanner checks should use tiny fixtures;
CI runs repository scans and full suites. Never put credential values in fixtures.

Primary references: https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/
and https://docs.semgrep.dev/cli-reference .

Real fixture checks are opt-in with `BUSBAR_SECURITY_TEST_DOCKER_HOST` set to an
existing local Unix endpoint. `test_scanner_tools.py` uses only tiny synthetic
files and preinstalled pinned images; it exercises clean/findings/parse failures,
no network route, read-only source and absent credentials/socket. With a fresh
pre-fetched database at `BUSBAR_SECURITY_TEST_DB`, the fixture also proves a known
vulnerable CycloneDX package refuses. It never pulls
images, downloads a database or scans the repository. Fixture output is not a
claim that the production runner or repository scan has passed.

## Standalone plugin-release evidence

`publish_gate.py plugin-release` now refuses before either signer unless the
`--plugins` directory contains `security-sboms.json` and one nonempty CycloneDX
SBOM per expected archive. The protected producer must generate these from the
actual build dependency closure. It has not been wired to emit them by this
change. This is a satisfiable input contract, not an optional flag:

```json
{
  "schema": "busbar.plugin-sboms/1",
  "repository": "GetBusbar/busbar-store-example",
  "version": "1.6.0",
  "source": "<exact 40-hex plugin commit from release/plugin-pins.tsv>",
  "subjects": [{
    "artifact": "busbar-store-example-1.6.0-x86_64-unknown-linux-gnu.tar.gz",
    "artifact_sha256": "<SHA-256 of the unsigned archive>",
    "sbom": "busbar-store-example-x86_64-unknown-linux-gnu.cdx.json",
    "sbom_sha256": "<SHA-256 of that exact SBOM>"
  }]
}
```

Include every declared `PLUGIN_TARGETS` archive exactly once. SBOM filenames must
be unique basenames ending `.cdx.json`, with no symlinks. CycloneDX
`metadata.component.name` and `.version` must match the pinned plugin and version;
`components` must be nonempty. Missing, reused, substituted or cross-plugin SBOMs
refuse. Each SBOM is independently scanned with the same pinned offline Trivy
policy, and the input inventory is rehashed afterwards.

The gate records scanned unsigned archive/SBOM hashes, source commit, database
and tool digests, then adds final sealed archive hashes to `plugin-security.json`.
K2 signs that evidence and SHA256SUMS, which also covers the published SBOMs.
Download verification compares the complete artifact/SBOM/evidence/signature set
with the locally verified release. This binds both pre-seal scan subjects and
post-seal distribution bytes; it is not SLSA provenance or SBOM completeness
certification. No standalone plugin signing or publication ran in this task.
