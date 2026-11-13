# Releasing Busbar

Develop on `dev`. QA/main promotion and signed publication require the owner's
explicit instruction. GitHub Actions is retired; GitHub is the public code mirror.
Current dev source and the active CI configuration define implemented behavior.
Superseded architecture documents and deleted `.ci/` branch files must not be
restored to reconstruct a release workflow.

## Current source entry points

- [Default distribution](dist/default/Cargo.toml): the assembled product and its
  plugin dependency graph. A core-only binary is not the complete distribution.
- [Product input builder](scripts/ci-product-inputs.sh) and
  [immutable input pins](scripts/ci-product-pins.json): build the actual artifacts
  used by product tests.
- [Candidate builder](scripts/release/candidate.py): assembles candidate artifacts.
- [Conformance gate](scripts/release/conformance_gate.py) and
  [registry](conformance/registry.toml): bind conformance evidence to the release
  and shipped plugin revisions. Consult the implementation for its required inputs
  and refusal behavior.
- [Publish gate](tools/publish-gate): `busbar-publish-gate`, the owner-run verify/sign/upload
  entry points. Build it in your own clone at the release commit with
  `cargo build --locked --release --manifest-path tools/publish-gate/Cargo.toml`, then run
  `tools/publish-gate/target/release/busbar-publish-gate --help` for the commands. Use that help
  and owner-provided signing configuration.
- [Native provenance](scripts/release/native_provenance.py) and
  [stage verifier](scripts/release/provenance_stage.py): verify protected inventories
  and exact artifact statements. Main verification reuses the qualified QA plans.
- [Provenance check fragment](ci/provenance-checks.yaml): configuration to integrate
  with protected CI. Its presence alone does not prove installation or a passing run.
- [Release trust](docs/design/release-trust.md): loader trust-chain implementation
  reference. Provisioning and qualification require their own evidence.
- [Verification guide](docs/verify.md): user-facing artifact verification.

This checkout does not contain the complete active CI control-plane configuration.
Read it from the authorized CI service when executing a release; do not infer live
branch protection, job coverage, signing readiness or publication from this document.
No cloud or signing credential is needed merely to edit core source or its design.

## Change and evidence discipline

Locally run formatting/linting and the few tests directly covering a change. Full
required suites run in native CI. Commit/push only when authorized, inspect CI results
and fix failures. A publication or green claim must identify the exact final product,
its dependencies and the passing evidence; a source build alone does not establish it.

Maintain [CHANGELOG.md](CHANGELOG.md) for release notes. Preserve historical migration
fixtures and published signed evidence. [CoreFix.md](CoreFix.md) is a forward design
on dev, not an implemented release or permission to promote QA/main.
