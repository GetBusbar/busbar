# OIDF OAuth / FAPI conformance

Run the official suite through trusted native CI with:

```sh
CONFORMANCE_TIMEOUT_SECONDS=14400 bash testing/conformance/run.sh
```

The core suite list invokes `python3 -I testing/oidf-conformance/oidf.py` for
`oidf-oauth2` and `fapi2`. Both identifiers report the same complete
`fapi2-security-profile-final-test-plan` execution with `openid=plain_oauth`,
`client_auth_type=private_key_jwt`, `sender_constrain=dpop`, and
`fapi_profile=plain_fapi`. This is OAuth authorization-server qualification;
it does not claim OpenID-provider certification. The rig shares the record only
when subject revision, tracked changes, rig bytes, pinned suite revision and
plan and mounted instrument manifest match. The driver clears its output before each invocation.

Isolated native CI stages instruments before candidate admission:

```sh
python3 scripts/architecture/stage_oidf_conformance.py \
  /controller-owned/oidf-inputs --architecture amd64 --image-source oci
```

The protected controller merges the resulting `inputs.json` with the other
measured bundles and supplies `--conformance-inputs` and its SHA-256 to the
native worker. OCI staging verifies the fixed image index, the selected Linux/amd64 manifest,
config and every layer digest, then applies layer whiteouts and resolves image
links inside the image. It records every regular file's hash and executable mode.
The alternate `--image-source docker` uses cached digest-pinned images or one
bounded pull and exports never-started containers. It also stages
the official runner at the pinned Git commit and verifies each runner wheel.
This controller step requires Git and public download access; the Docker source
option also requires Docker 29.1.3.

The candidate receives `/opt/busbar-conformance/oidf` read-only. Its JVM, MongoDB,
nginx, Python runner and subject run as unprivileged processes in the same
isolated loopback namespace. Each binary uses its image's own ELF loader and
libraries. The worker provides fixed loopback aliases for `localhost.emobix.co.uk`
and `busbar.oidf.test`; the adapter checks these before starting. The official
nginx TLS/mTLS configuration keeps its headers and policy while relocating its
paths and upstream. A run-local JVM trust store trusts the subject's throwaway CA.
The candidate needs no Docker executable, socket, external network or credentials.
Missing or mismatched native inputs fail closed, without attempting downloads.

The distribution-locked OIDC plugin source is a separate measured `oidc-source`
bundle containing its source files and `source-identity.json` (`url`, `rev`).
The adapter verifies its identity before copying it to the writable build area.
Cargo dependencies and the Rust toolchain must already be hydrated; native builds
use Cargo offline mode. Allow memory for MongoDB, the suite JVM and compilation.

Direct invocation outside native CI retains the Compose path and requires Docker
Compose v2, host-gateway support, Git, Cargo and network access to the pinned
sources. Both paths accept `CONFORMANCE_OUT`, `BUSBAR_CHECKOUT`, `CARGO_TARGET_DIR`
and `MODERNCI_CACHE_DIR`. Keep disposable local probes under
`/Users/matthew/Developer/tmp/`. The full subject and negative-control plans run
in CI on the intended architecture; an ARM instrument smoke is not an amd64 pass.

The instrument is official `release-v5.3.3`, source commit
`7d420f716e49d44f8a6b04f0a3e240ad6d68ab55`, with all four container images and
runner wheels pinned by digest in `oidf.py`. Its positive control copies the
pinned suite's own RP-against-OP CI pairing. Its negative control requires
both named discovery and happy-flow modules to fail against FAPI-disabled
busbar. The subject uses the shipped `dist/default` binary and the OIDC module
at that distribution's locked revision.

Each newly owned memory Store uses the product's principal inspection CLI and
an explicit creation receipt, then initializes and serves in one process/open.
An inspection's empty state does not establish freshness. Inspection output,
creation evidence and the receipt remain beside the generated subject config.

A clean subject pass requires every module's exported terminal result. Warnings,
missing exports and unexplained skips fail. A REVIEW passes only for the exact
page hash already signed by the owner in `signoff.json`. Changed pages need a
new owner review; the rig never changes sign-offs itself. Raw exports, logs and
review pages remain in the conformance output for diagnosis.

Targeted rig checks (no official suite execution):

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/Users/matthew/Developer/tmp/<task> \
  python3 -B -I testing/oidf-conformance/test_oidf.py
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/Users/matthew/Developer/tmp/<task> \
  python3 -B -I testing/oidf-conformance/test_native.py
```
