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
- [Conformance registry](conformance/registry.toml) and
  [manifest renderer](scripts/conformance/sync.py): bind conformance evidence to the
  release and shipped plugin revisions.
- [Release verifier](scripts/release/release_verifier.py) and
  [native provenance](scripts/release/native_provenance.py): verify a release's signed
  inventory and exact artifact statements; [scripts/verify-artifact.py](scripts/verify-artifact.py)
  uses them.
- [Release trust](docs/design/release-trust.md): loader trust-chain implementation
  reference. Provisioning and qualification require their own evidence.
- [Verification guide](docs/verify.md): user-facing artifact verification.

The release process itself (candidate assembly, the conformance and publish gates,
signing and publication) and the CI configuration are owner-maintained tooling outside
this repository. Do not infer live branch protection, job coverage, signing readiness
or publication from this document.
No cloud or signing credential is needed merely to edit core source or its design.

## Change and evidence discipline

Locally run formatting/linting and the few tests directly covering a change. Full
required suites run in native CI. Commit/push only when authorized, inspect CI results
and fix failures. A publication or green claim must identify the exact final product,
its dependencies and the passing evidence; a source build alone does not establish it.

Maintain [CHANGELOG.md](CHANGELOG.md) for release notes. Preserve historical migration
fixtures and published signed evidence. [CoreFix.md](CoreFix.md) is a forward design
on dev, not an implemented release or permission to promote QA/main.
