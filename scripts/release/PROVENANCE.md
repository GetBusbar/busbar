Native QA/main provenance integration packet

Status: implemented and fixture-tested, not activated. No production signature,
public Rekor write, QA/main move, or SLSA Build level claim has been made.
This packet does not edit native controllers, engine crypto, SDKs, or website rows.

Files intended for dev:
  scripts/release/native_provenance.py
  scripts/release/provenance_stage.py
  scripts/release/test_native_provenance.py
  ci/provenance-checks.yaml (merge check map into protected CI configuration)

Protected execution contract

The native controller, or future ModernCI trusted control plane, must freeze an
artifact inventory independently of candidate code. Mount the producer/verifier,
inventory, expected plans, trust configuration and input files read-only in a
separate trusted step. Pin the producer/verifier bytes in that step's definition.
Do not run this verifier from an untrusted candidate checkout. Do not execute
candidate binaries in the signer step. Signing credentials never enter a build
worker. The producer does not provision infrastructure or retrieve private keys.

Each plan contains these exact binding fields:
  stage: qa
  source_commit: full lowercase 40-hex Git commit
  target: native Rust target triple
  builder_id: urn:busbar:builder:native-controller:v1
  invocation_id: public-safe opaque unique label
  artifact_name: public-safe basename
  artifact_sha256: lowercase SHA-256 of collected exact artifact bytes
  started_on/finished_on: controller-observed UTC RFC3339 build timestamps
  inputs: object with SHA-256 values for every one of:
    source-archive, source-file-map, lockgraph, build-recipe, toolchain,
    builder-receipt

The receipt repeats those fields and includes exit_code: 0, native: true,
host_target equal to target, and started_on/finished_on UTC RFC3339 timestamps.
The controller must derive these from completed execution, not candidate claims.
Input file mapping is a private JSON object from each of the six input names to
its actual local file. Every file is rehashed against the independent plan.
builder-receipt is the underlying controller evidence, not this normalized
receipt; this avoids a self-referential digest.

Native output mapping:
  source-archive <- frozen core-source.tar.gz
  source-file-map <- frozen core-source-files.json
  lockgraph <- exact normal resolved dependency/lock evidence for this build
  build-recipe <- terminal build commands and effective environment/config
  toolchain <- actual rustc/cargo/linker/tool/image identity evidence
  builder-receipt <- completed controller platform/run/start/end/exit evidence
  artifact <- collected binary/archive, independently hashed after transfer

The currently inspected C/source-freeze.json provides commit plus archive/map
digests only; it is not a completed build receipt. It must not be promoted into
provenance by filling the missing fields with guesses. Existing build receipts
are private evidence. Their content is never copied into a public statement.

QA inventory JSON schema (paths are operator-local, never public):
  {"version":1,"stage":"qa","artifacts":[{
    "plan":"/trusted/plan.json","plan_sha256":"<64 hex>",
    "receipt":"/collected/receipt.json",
    "input_files":"/trusted/input-files.json",
    "artifact":"/collected/busbar-<target>",
    "statement":"/output/provenance.intoto.json",
    "bundle":"/output/provenance.sigstore.json",
    "sigstore_config":"/trusted/sigstore.json",
    "sigstore_config_sha256":"<64 hex>"
  }]}

All actual release artifacts must appear in this protected inventory; its
completeness is the controller's responsibility. Empty/duplicate sets fail.
The controller supplies the inventory SHA-256 separately from candidate output.

Call from the current native trusted control plane:
  python3 scripts/release/provenance_stage.py prepare qa \
    --manifest /trusted/qa-inventory.json --manifest-sha256 <inventory digest>

This creates canonical in-toto Statement v1 / SLSA provenance v1 files, with
content URNs rather than private Forgejo URLs or local runner paths. Artifact
name/digest, source revision, target, stage, builder ID, invocation, timestamps
and six input digests are public. The source and input bytes remain private.
Recipe and lockgraph hashes commit to inputs without exposing their contents.
The build-type URI identifies this exact schema. The builder URI identifies the
native operator/controller/worker trust boundary; it is not an OIDC identity
or a claim that the builder meets a SLSA level. Document the deployed boundary
and completeness/isolation guarantees before claiming a level.

After the separately trusted signing step supplies real bundles, run:
  python3 scripts/release/provenance_stage.py verify qa \
    --manifest /trusted/qa-inventory.json --manifest-sha256 <inventory digest>

Main inventory has stage: main and the same exact QA plan digests/artifact set,
plus qualified_qa_inventory and qualified_qa_inventory_sha256. Main runs verify
main with its protected inventory digest. It re-verifies all bundles and bytes;
it cannot prepare new statements or accept a rebuild with a different plan.

ModernCI interface

ci/provenance-checks.yaml uses the existing checks/run branch-file schema.
Merge it with the full protected QA/main configuration; it is not a replacement
branch file and does not change promotion policy. Register qa-prepare after
artifact collection, qa-verify after trusted signing, and main-verify before
publication. Run signing outside ordinary candidate checks. The same stage CLI
works from the current native controller; ModernCI availability is not required.
Wire the named checks into the existing on.move/on.landed sequences only when
that QA/main stage is activated. These are executable failing checks, not green
placeholders: missing inputs, signer trust or bundles are failures.

Existing tooling-key adapter (separate from Sigstore)

native_provenance.py sign and verify-signature preserve console-ops' exact
basename + newline + sha256 + newline message format. They pin the established
tooling public-key DER SHA-256
729b1f2a42d3b73de464a4b38abfcc3b9e9d49af2944d1450bceed70a37defd0
and require the signer executable digest from its custody receipt. The private
key stays in the existing OpenBao/operator step. No key recovery, export, import,
rotation or new trust root is performed. This adapter is for tooling provenance;
using that key for a different product/purpose needs explicit authorization.
A detached signature does not count as a Sigstore bundle or Rekor inclusion.

All native_provenance.py operations take --plan, --receipt, --input-files,
--artifact and --statement. The sign operation also takes --signature,
--public-key, --signer and --signer-sha256. verify-signature takes --signature
and --public-key. No signing operation is run by the prepare/verify stage CLI.

Sigstore adapter

Production sigstore.json fields:
  version: 1
  builder_id: exact permitted builder ID for this signer
  cosign: absolute pinned cosign executable path
  cosign_sha256: digest of that executable
  trusted_root: absolute Sigstore trusted_root.json path
  trusted_root_sha256: digest of the root obtained by a trusted operator/TUF flow
  mode: key OR identity
  key mode: public_key file MUST match the existing tooling-key fingerprint
  identity mode: identity and issuer MUST name an existing authorized identity

Signing additionally requires signing_config + signing_config_sha256, and either
an existing key_handle (supported KMS/transit/PKCS11 URI) or identity_token_file
in the trusted step. Raw private-key paths and ambient identity discovery are
not accepted. The current OpenBao KV key record is NOT a Vault transit key, and
console-ops' basename/digest API is NOT a DSSE signer. No compatible existing
cosign handle or authorized non-GitHub OIDC identity was established here.
That is a concrete activation prerequisite, not an implemented deployment.

native_provenance.py attest requires --sigstore-config, --bundle and
--approved-public-sha256 matching the exact public statement digest. Before
activation review the full statement plus any certificate identity that would
be disclosed. Public logging is irreversible. This task executes no such call.
The actual adapter uses cosign attest-blob --statement and then verifies the
result with cosign verify-blob-attestation. Bundle payload must be the exact
expected statement bytes. A real Rekor inclusion proof/checkpoint is mandatory,
and cosign must validate it against the pinned Sigstore root. Merely having log
fields does not pass; no production insecure-ignore-tlog option exists.

Activation prerequisites and existing release fence

1. Integrate these files into dev and pin them in the protected producer step.
2. Export completed native receipt/inputs and a separately trusted expected plan.
3. Select an existing authorized compatible Sigstore signer identity/service;
   the current operator Ed25519 API alone cannot supply DSSE.
4. Provision pinned Cosign, Sigstore root and signing configuration in the
   trusted signing step, and approve the exact public metadata/identity.
5. Invoke the QA/main checks through protected native/ModernCI stage routing.
6. Replace publish_gate.py's current explicit G-9 provenance refusal only as
   part of the owner-authorized QA/main activation, with this verification gate
   mandatory for every published artifact. Preserve all other release gates.
   The current release fence was deliberately left intact; this packet cannot
   accidentally enable publication or change the current release evidence.

Validation

python3 -m unittest discover -s scripts/release -p test_native_provenance.py -v
Tests use temporary fixture Ed25519 keys, never production trust. Real installed
Cosign 3.1.4 verifies the DSSE fixture offline and rejects artifact tampering.
Only that isolated fixture test disables tlog; production refuses unlogged
bundles. Tests also cover source/input/builder mismatch, privacy, invalid native
receipts, detached signature/name binding, signer executable pin, duplicate
JSON keys, inventory substitution, main rebuild and public-payload substitution.
No live transparency-log inclusion was tested or claimed.

Primary references consulted:
https://slsa.dev/spec/v1.1/provenance
https://slsa.dev/spec/v1.2/provenance
https://docs.sigstore.dev/cosign/signing/signing_with_blobs/
https://docs.sigstore.dev/cosign/verifying/verify/
https://github.com/sigstore/cosign/blob/v3.1.4/cmd/cosign/cli/attest/attest_blob.go
