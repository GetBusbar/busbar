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
plan match. The driver clears its output before each invocation.

Prerequisites:

- Docker Engine with Compose v2, an accessible daemon, and host-gateway support.
- Git, Cargo and the checkout's Rust toolchain, plus native build dependencies.
- Network access to GitLab's official OpenID suite/source registry, PyPI wheel
  storage, and the exact Git/Cargo sources in the distribution lockfile.
- Enough memory for MongoDB, the suite JVM, and compilation. The subject's TLS
  listener must be reachable from Docker through its host gateway. The rig
  allocates ports, creates its own network and removes its Compose services.
- A dedicated output directory and target/cache locations belonging to the CI
  job. Direct invocation accepts `CONFORMANCE_OUT`, `BUSBAR_CHECKOUT`,
  `CARGO_TARGET_DIR` and `MODERNCI_CACHE_DIR`; keep disposable local probes under
  `/Users/matthew/Developer/tmp/`. The full suite runs in CI.

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
```
