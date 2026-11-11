Native QA/main provenance integration packet

Status: implemented and fixture-tested, not activated. No production signature,
public Rekor write, QA/main move, or SLSA Build level claim has been made.
This packet does not edit native controllers, engine crypto, SDKs, or website rows.

Files intended for dev:
  scripts/release/native_provenance.py
  scripts/release/provenance_stage.py
  scripts/release/test_native_provenance.py
  scripts/release/release_verifier.py
  scripts/release/release_producer.py
  scripts/release/test_release_producer.py
  scripts/release/oci_provenance.py
  scripts/release/test_oci_provenance.py
  scripts/release/test_release_verifier.py
  scripts/release/test_artifact_provenance.py
  scripts/verify-artifact.py (native provenance row; release/artifact-contract.json)
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

Existing tooling Sigstore configuration fields:
  version: 1
  builder_id: exact permitted builder ID for this signer
  cosign: absolute pinned cosign executable path
  cosign_sha256: digest of that executable
  trusted_root: absolute Sigstore trusted_root.json path
  trusted_root_sha256: digest of the root obtained by a trusted operator/TUF flow
  mode: key OR identity
  key mode: public_key file MUST match the existing tooling-key fingerprint
  identity mode: exact https://github.com issuer and local signing project's
    //.gitlab-ci.yml@refs/heads/main identity; no regex, alias, or GitHub identity

Prepared release-specific configuration uses version: 2 and
purpose: release-attestation, retaining the executable/root/builder fields above.
Key mode additionally requires public_key_sha256 (DER SubjectPublicKeyInfo SHA-256)
and key_algorithm: ed25519 OR ecdsa-p256-sha256. The actual key type/curve must
match. Version 1 and detached tooling signatures still accept only TOOLING_KEY.
The new schema does not select or provision a production key. The whole trust
configuration digest must be independently approved, not fetched as its own
trust authority beside untrusted release assets.

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
The public inventory tests additionally verify a real custom-predicate DSSE
signature offline, reject tampering, missing/extra/reused/symlinked files, wrong
SBOM release identity, trust substitution and mutation during verification.
Run test_release_verifier.py and test_artifact_provenance.py with the same
unittest discovery invocation. No live transparency-log inclusion was tested or claimed.

Primary references consulted:
https://slsa.dev/spec/v1.1/provenance
https://slsa.dev/spec/v1.2/provenance
https://docs.sigstore.dev/cosign/signing/signing_with_blobs/
https://docs.sigstore.dev/cosign/verifying/verify/
https://github.com/sigstore/cosign/blob/v3.1.4/cmd/cosign/cli/attest/attest_blob.go

GitLab-native signing design (2026-11-10; proposed, not activated)

Decision: use GitLab to authorize a separate release-attestation signer. Prefer a
purpose-specific non-exportable KMS key and Cosign DSSE bundles as the first
release path; retain self-hosted Fulcio as an alternative if certificate-based
GitLab identity is required. GitHub remains an optional artifact distributor.
Neither GitHub Actions nor `gh attestation` participates in trust or production.
The public OIDC discovery endpoint was read on 2026-11-10 and returned exactly:
  issuer: https://github.com
  jwks_uri: https://github.com/oauth/discovery/keys
Re-read authenticated HTTPS discovery during activation, verify JWT signatures
against that issuer's JWKS, and reject issuer aliases or trailing-slash changes.
Never accept a decoded JWT without signature, audience and lifetime validation.

Trust and job separation

Proposed signing project: GetBusbar/release-signing (not created by this work).
Its local .gitlab-ci.yml is owner-controlled, on protected main, pinned by an
independently approved commit. Only this dedicated project gets signer access.
Build projects, MR pipelines, fork pipelines and ordinary developers cannot
modify its configuration, trigger arbitrary scripts, choose an identity, change
trust roots, or provide pipeline variables overriding the approved manifest.
Keep id_tokens in this signing project's own top-level file: do not reuse the
external architecture CI include as a signing identity. GitLab documents identity
limitations for externally included signing configuration.

The signer job receives a controller-selected inventory digest, reads completed
GitLab jobs by immutable project/pipeline/job ID, verifies their actual status,
source vector and policy revision, then fetches artifacts by those job IDs. No
branch-name "latest artifact", CI dotenv from candidate output, executable from
a build artifact, or candidate script runs here. Restrict job-token artifact
access to the specific producer projects. Disable untrusted pipelines on this
project and protect the release-attestation environment. Use a fresh signer VM
with no shared HOME, Cargo cache, workspace, daemon or mounted build-worker disk.
The signer holds no merge credential; the publisher receives verified bundles
and cannot use the signer key. Main re-verifies the identical QA bytes and plans;
it does not rebuild or rewrite a QA statement to claim a new build.

Artifact transfer does not establish build integrity. The trusted controller
must observe command execution and collect outputs outside candidate-writable
namespaces. A separate signing job stops post-build credential theft, but cannot
make a candidate-written receipt authoritative. Reject a release until that
controller boundary is qualified. The native constraints below are still real.

KMS route (recommended deployment design)

Use GitLab id_tokens with a single audience, chosen here as
  https://github.com/busbar-release-attestation
and a Google Workload Identity Federation provider with that exact allowed
audience and the discovery issuer above. This is a proposed audience, not a
claim that the provider already exists. GCP is an option consistent with the
existing forge environment; no cloud project, account, key or role is inferred.
An approved AWS KMS or OpenBao transit key can serve the same DSSE role if its
separately reviewed federation and key policy provide equivalent restrictions.
Cosign supports KMS handles; an OpenBao KV record is not a transit signing API.
[Cosign KMS reference](https://docs.sigstore.dev/cosign/key_management/overview/)

For GCP, map google.subject=assertion.sub and job_project_id/project_id,
project_path, ref_path, ref_protected, ci_config_sha, pipeline_source,
environment and environment_protected. The provider's attribute condition must
require ALL of the following; missing claims refuse:
  job_project_id == independently recorded numeric signing project ID
  project_id == that same ID
  project_path == "GetBusbar/release-signing"
  ref_path == "refs/heads/main" AND ref_protected == "true"
  ci_config_sha == the approved signer-config commit
  pipeline_source == "api"
  environment == "release-attestation" AND environment_protected == "true"
Pin actual types from a signature-validated token on the deployed GitLab version;
GitLab added job_project_id in 18.4. Do not silently drop unavailable claims.
The controller starts the API pipeline only for an approved immutable inventory.
Restrict impersonation of a dedicated signer service account to this provider
and project identity, and grant that account only asymmetric signing/public-key
read on the dedicated release-attestation CryptoKey, never key administration,
key creation, private-key export, storage write or broad project roles. The key
version is part of the approved trust tuple. A candidate VM must have neither
this federation identity nor an attached signing-capable service account.
[GitLab ID-token claims](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
[Google federation configuration](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)

Protected job sketch, intentionally not included in active CI:
  attest-qa:
    environment: release-attestation
    id_tokens:
      RELEASE_ID_TOKEN:
        aud: https://github.com/busbar-release-attestation
    # local immutable signer code exchanges ID token via federation, then runs
    # the pinned producer/signing adapter; no candidate checkout or shell import.

Short-lived credentials go in a mode-0600 task-local file for ADC; no token in
command-line arguments, debug logs, artifacts or dotenv. Expire/remove credentials
when the one-shot job finishes. Public verification pins the exported public
key's DER SHA-256 from an independently approved custody record; downloading a
public key beside an untrusted bundle is not a trust bootstrap. The KMS signature
proves possession of that key, not a Fulcio OIDC identity. GitLab authorization
and KMS audit logs remain separate private operational evidence.

After the owner approves actual key and log configuration, the signing command
shape is (variables here denote protected configuration, not candidate values):
  cosign attest-blob --statement provenance.intoto.json \
    --key "$RELEASE_KMS_URI" --bundle provenance.sigstore.json \
    --signing-config signing-config.json --trusted-root trusted-root.json \
    --oidc-disable-ambient-providers --yes
Retain Rekor inclusion proof and checkpoint and verify immediately. Public
logging discloses the signed statement and public key; use a private Rekor root
if that disclosure is not approved. A private log must have retained durable
state, independently distributed trusted keys and checkpoint monitoring; an
unmonitored operator-controlled log is not independent public transparency.

`native_provenance.py` version 1 still pins Ed25519 TOOLING_KEY. Version 2 now
accepts an independently pinned release-specific Ed25519 or P-256 public key,
with purpose and algorithm checks, without broadening tooling trust. Its existing
KMS-handle signing command verifies the resulting DSSE immediately. No actual
release key, key version, federation or log configuration has been selected or
activated. Do not change TOOLING_KEY to reuse the plugin trust root. The existing
`sign-kms.sh` signs plugin key documents and is not a release-attestation DSSE adapter.

Fulcio route (alternative, explicit new infrastructure decision)

The public Sigstore Fulcio service does not trust arbitrary Self-Managed GitLab
issuers. Either operate approved Fulcio + Rekor + CT services, or obtain explicit
trust onboarding; merely setting --certificate-oidc-issuer does not onboard it.
For a self-hosted stack, configure the exact issuer https://github.com,
client-id sigstore, ci-provider GitLab claim mapping, and use id_tokens aud:
sigstore only in the protected signing project. Preserve trusted Fulcio CA chain,
CT public keys and Rekor public keys in an independently pinned trusted_root.json,
plus signing endpoints in signing-config.json. Keep CA/log keys and persisted
log state under separate custody from build and signer workers. Never disable
SCT or tlog verification to work around an incomplete deployment.
[GitLab Self-Managed Sigstore setup](https://docs.gitlab.com/ci/yaml/signing_self_hosted/)
[Cosign custom trust configuration](https://docs.sigstore.dev/cosign/system_config/custom_components/)

With the proposed local signing configuration, the EXACT allowed certificate
identity is:
  https://github.com/GetBusbar/release-signing//.gitlab-ci.yml@refs/heads/main
and the EXACT allowed issuer is:
  https://github.com
The double slash is intentional. Verify this expected identity against a staging
certificate before activation, without logging JWTs. No broad regex, project-only
identity, GitLab.com issuer or candidate-controlled ci_config_ref_uri is accepted.
Fulcio maps GitLab ci_config_ref_uri to SAN; the GitLab JWT sub alone is NOT the
certificate identity. Pin the expected config digest and authenticated execution
claims at signer authorization; issuer + SAN verification by itself does not
verify protected-ref status, source commit or intended release inventory.
Standard certificate extensions expose signer/source project URLs, commit, ref,
job URL and visibility: using the dedicated signing project avoids exposing the
private source repository through the signing job's certificate, but still
reveals the signer project/forge hostname. Approve that exact metadata first.
[Fulcio GitLab identity mapping](https://github.com/sigstore/fulcio/blob/main/docs/oidc.md#gitlab)

Private source, SBOMs and artifact binding

The public predicate contains the public artifact name + actual SHA-256, source
commit/content digests, public-safe builder URN, build recipe/toolchain/lockgraph
hashes and opaque invocation ID. Keep source archives, file maps, internal GitLab
job URLs, paths, usernames, tokens, recipe text and dependency-server credentials
private. Hashes commit to private inputs; they do not prove those inputs were
actually used. The protected controller and qualified execution boundary provide
that linkage. Review SBOM fields before publication: package names, versions,
licenses, purls and source URLs may disclose private dependency inventory.

Use one SLSA statement per final downloadable artifact. OCI subjects must bind
the registry index digest AND the platform manifest digests actually shipped;
SHA-256 of an OCI tar is useful transport evidence but is not the registry digest.
Produce a separate signed release-evidence statement whose subject is the final
canonical release inventory. Its inventory lists every artifact, corresponding
SBOM SHA-256, OCI index/platform digest, provenance statement/bundle digest,
source/policy revision, conformance receipt digest, scanner tool/database digest
and scan timestamp. The inventory is generated by trusted collection, never by
letting candidate.json define its own required subjects. Publish the inventory,
bundle, artifact provenance bundles and SBOMs together, with immutable digest
addressing and supported-release-lifetime retention.

Bind the SBOM to its artifact in that inventory and a CycloneDX in-toto statement
with the artifact as subject. Signing an unrelated SBOM file alone is insufficient.
The producer must compare SBOM package closure with actual resolved/build and
image contents before signing. Trivy G-S scans the SBOM and OCI bytes, refuses
known HIGH/CRITICAL findings and records hashes, but cannot detect a dependency
omitted from a supplied SBOM. Existing G-3/G-4/G-8/G-10 and conformance retain
closure responsibility. The current provenance v1 adapter has six fixed input
digests. release_producer.py now collects verified QA files, emits artifact-bound
CycloneDX statements and OCI index statements, then finalizes the public aggregate
inventory only after their real logged bundles verify. It cannot manufacture
build closure, host isolation observations or production signing authority.

Consumer commands replacing `gh attestation`

A consumer installs independently authenticated release trust (Cosign executable,
public key or Fulcio root, Rekor/CT trust, accepted builder/build-type and source
policy) before downloading candidate-controlled data. For the proposed KMS path:
  cosign verify-blob-attestation --bundle provenance.sigstore.json \
    --key release-attestation.pub --trusted-root trusted-root.json \
    --type https://slsa.dev/provenance/v1 ./busbar-TARGET.tar.gz
For the Fulcio alternative:
  cosign verify-blob-attestation --bundle provenance.sigstore.json \
    --trusted-root trusted-root.json --type https://slsa.dev/provenance/v1 \
    --certificate-oidc-issuer https://github.com \
    --certificate-identity 'https://github.com/GetBusbar/release-signing//.gitlab-ci.yml@refs/heads/main' \
    ./busbar-TARGET.tar.gz
For a registry attestation, use `cosign verify-attestation --type
https://slsa.dev/provenance/v1` with the same approved trust selector and the full
`REGISTRY/IMAGE@sha256:DIGEST`, never a tag. Exact flags above were checked against
installed Cosign 3.1.4 help; live GitLab certificates/KMS bundles have not been
produced. The existing fixture proves real offline DSSE verification only.
[Cosign verification reference](https://docs.sigstore.dev/cosign/verifying/verify/)

Cryptographic success alone is insufficient. Apply the repository verifier's
expected plan comparison to require the exact builder_id, buildType, source
commit, target, six input digests, artifact digest and QA-qualified inventory.
The prepared public consumer adapter verifies the aggregate download inventory
and SBOM-to-artifact mapping as described below. Inventory v2 additionally checks
OCI export closure, platform/native mappings and the exact registry attestation.
Scanner freshness and actual in-image native binary equivalence still belong to
the protected release gate; OCI metadata alone does not establish them. Refuse missing/extra subjects, wrong
builder/predicate, substituted source/policy/target, stale scan evidence,
untrusted key/root, missing log proof or changed QA artifact. No
--insecure-ignore-tlog, issuer wildcard or trust-on-first-download fallback.

Prepared public download verifier (implemented, not activated)

Run with trusted Python cryptography and the independently pinned Cosign executable:
  python3 scripts/release/release_verifier.py \
    --directory ./downloaded-release \
    --inventory-sha256 <independently-approved-release-inventory-digest> \
    --trust /trusted/release-sigstore.json \
    --trust-sha256 <independently-approved-trust-configuration-digest>

Keep the directory private during verification and through use of its verified
bytes. It must contain exactly release-inventory.json,
release-inventory.intoto.json, release-inventory.sigstore.json, and the listed
artifact/SBOM/statement/bundle files. Extra, missing, reused and symlinked files
refuse. Never derive the expected inventory/trust digests from the same untrusted
download without independently authenticating them. Run trusted verifier code,
not a script supplied by the release being checked.

The public inventory has schema: busbar.release-inventory/1, release: 1.6.0,
and artifacts: a nonempty list. Each entry has exactly:
  plan: the public QA plan fields listed above, without private paths/receipts
  component_name: expected CycloneDX metadata.component.name
  statement: {name: <basename>, sha256: <digest>}
  bundle: {name: <basename>, sha256: <digest>}
  sbom: {name: <basename>, sha256: <digest>}
The artifact basename/digest are in plan. Each basename is unique across the
entire release. The SBOM must be CycloneDX, have a nonempty components list,
and match component_name plus release version. Per-artifact statement bytes
must equal the canonical native statement reconstructed from the approved plan.
This checks signed assertions, not actual private input bytes or build execution.

The aggregate statement is an in-toto Statement v1, with the sole subject
release-inventory.json and its SHA-256, predicateType:
urn:busbar:release-inventory:v1, and predicate: {release, builder_id}.
release_verifier.inventory_statement constructs these canonical public fields;
the protected producer must supply the independently approved complete inventory
and obtain its real logged DSSE bundle. This custom release inventory is not
itself SLSA build provenance. Every artifact still requires its native SLSA bundle.
Both kinds of bundle require cryptographically verified log inclusion/checkpoint.

scripts/verify-artifact.py's attestation row now calls this same verifier with
--provenance-directory, --provenance-inventory-sha256, --provenance-trust and
--provenance-trust-sha256. It additionally matches the selected archive digest,
name, target and version to a verified inventory subject. Absent activation
inputs fail closed. The obsolete GitHub workflow identity/environment override
is removed; the contract default now points to release/artifact-contract.json.
The existing publish_gate.py G-9 refusal is unchanged.

Prepared OCI consumer extension

busbar.release-inventory/2 adds an oci list and requires each artifact entry's
sbom_statement and sbom_bundle file bindings. The SBOM statement uses the official
https://cyclonedx.org/bom predicate with that artifact as subject and the exact
published CycloneDX document as predicate. Each OCI entry has reference (immutable
registry/name@sha256:index), platforms (linux/amd64 or linux/arm64 mapped to native
artifact basenames), and archive/index/statement/bundle file bindings.

oci_provenance.py hashes the OCI tar without extracting it. It rejects links,
traversal, duplicate files, foreign layers, missing/extra blobs, descriptor size
or digest mismatches, platform/config disagreement and wrong native target maps.
It binds the actual index, configuration and layer digests to a custom
urn:busbar:oci-release:v1 statement, verifies its logged bundle against the exact
index bytes, then uses pinned Cosign verify-attestation on the immutable registry
reference and requires exactly matching statement payloads. Registry access is
read-only; missing or conflicting verified attestations refuse. This is not a
claim that registry production signing is qualified. The current v3 extension below
adds byte-level image/native equivalence; v1/v2 consumers report that property false.
The 5 targeted OCI fixtures cover closure and refusal cases; live registry
signature/log verification remains a deployment witness, not a mocked-test claim.

Protected producer interface (implemented, no signing or registry writes)

release_producer.py consumes an independently pinned private plan with schema:
busbar.release-publication/2, release, qa_manifest: {path, sha256}, subjects,
oci, isolation_policy_sha256 and isolation_observations. subjects maps every
independently required artifact basename to {component_name, build_closure,
build_capture}; it must exactly equal the qualified QA artifact set. build_closure
is a {path, sha256} binding. build_capture has cargo_metadata, cargo_lock,
cargo_messages and binary, each an independently collected {path, sha256} binding,
plus compiler_output naming the original absolute compiler output path. The latter
is controller-selected so copied binaries can be verified outside the candidate
mount without rewriting the captured Cargo stream.
oci entries have reference, platforms and archive: {path, sha256}; each platform
now maps to {artifact: <native archive basename>, member: <compiled archive member>,
path: <absolute image entrypoint>}. All input paths are absolute regular files;
collection rejects links/devices and existing outputs and hashes copied bytes.

isolation_observations maps every native artifact to a separately collected,
digest-pinned host observation. Its schema is busbar.native-execution-observation/1
with the approved policy_sha256, matching builder_id/source_commit/invocation_id/
artifact_sha256, nonzero candidate_uid, exit_code: 0, runtime_sha256,
toolchain_image_sha256 and finished_on no earlier than the build's finish.
Its controls must be exactly true for controller_separated,
private_pid_mount_network, policy_readonly, receipts_unmounted,
no_host_docker_socket, no_metadata_credentials, descendants_reaped and
collected_regular_files. The trusted planner must fetch this from an independent
host observer, never copy candidate receipt fields or accept a candidate-selected
digest. Digest comparison preserves that external trust decision; it does not
turn self-reported booleans into independent evidence. A compatible core host
observer is still required engineering and has not been deployed by this work.
The deployed native path records host-subprocess/isolated:false/release_eligible:false.
The new opt-in Docker path records controller-observed confinement and remains
release_eligible:false; neither substitutes for the independent host observation.

Prepare rechecks the real private QA receipt/input files and native bundles:
  python3 scripts/release/release_producer.py prepare \
    --input /trusted/publication.json --input-sha256 <approved digest> \
    --output /collected/public-release --result /trusted/publication-draft.json
It emits collected native files, SBOM/index statements and private signing_requests.
No key is loaded and no signature, log entry or registry write occurs. A protected
signer must check each exact request digest and approved metadata, then use
Cosign attest-blob --statement for SBOM statements. OCI requests additionally
provide registry_reference and use Cosign attest --statement with that immutable
reference, the exact custom predicate type, pinned signing/trust configuration
and --bundle. These commands require separately authorized signing and registry
publication; this task invokes neither. Cosign 3.1.4 installed help confirms its
attest command accepts a complete --statement, preserving exact payload bytes.

After independently approved signing supplies the requested bundles:
  python3 scripts/release/release_producer.py finalize \
    --input /trusted/publication-draft.json --input-sha256 <approved draft digest> \
    --output /collected/public-release --trust /trusted/release-sigstore.json \
    --trust-sha256 <approved trust digest> --result /trusted/inventory-request.json
Finalization rechecks copied bytes, all native/additional bundles, complete file
inventory and registry attestations before emitting the aggregate inventory and
its statement. It explicitly returns publication_ready:false. The protected
signer must then sign that final aggregate statement; independent download
verification must pass release_verifier.py before any promotion. Private plans,
observations and signing requests remain outside the public output directory.
G-9 remains unchanged; these interfaces cannot publish a release by themselves.

Activation work, with exact missing inputs

1. Qualify the native controller/candidate isolation below and produce completed
   independent plan/receipt/input files for each immutable artifact.
2. Record owner-approved signing project numeric ID, immutable local config SHA,
   protected-ref/environment policy and controller invocation authority. Validate
   actual token claims and exact issuer before creating federation bindings.
3. Record selected cloud project/account, federation provider resource, signer
   service account, dedicated key/version URI, key algorithm + DER fingerprint,
   custody/rotation/revocation owner, and signer runtime image/executable digests.
   These values are not available from source; none was guessed or provisioned.
4. Select public or private log, approve exact published metadata, pin trust and
   signing configuration bytes, retention and checkpoint monitoring responsibility.
5. Deploy the prepared release-specific KMS trust adapter with actual approved
   trust (or activate independently managed Fulcio roots/identity). Complete
   live producer deployment using the implemented collection, SBOM/OCI statement
   emission, aggregate finalization and registry verification interfaces. Supply
   independently collected native-isolation observations and actual build/image
   closure evidence; the producer refuses absent isolation evidence. The standalone
   plugin-release G-S validator accepts artifact-bound per-target SBOMs. The protected
   producer now derives Cargo SBOMs from captured final builds; qualify the full
   target/vector and non-Cargo native dependency inventories in CI. Prove real staging
   negative cases: wrong issuer/ref/config/project/key, tampered artifact/SBOM,
   forged receipt, missing subject and QA/main substitution.
6. Only after explicit QA/main authorization wire protected signer/publisher jobs
   and replace G-9's refusal with mandatory verification for every final subject.
   This source change does not schedule or run production signing or promotion.

Native boundary required before provenance activation

Retained rollout evidence establishes runner 33's real runsc/UID-1000 Console
execution, measured image/closure, unshadowed protected paths and automatic
VM/disk retirement: project 46, pipeline 1365, successful jobs 2237 and 2249.
The immutable builder image digest is
83a5fc11d5ad73acc645e600029767fa8d0ed42eb1b0ca4056f0d49c363ae594.
The same pipeline's overall status is failed, confirmed by live GitLab readback.
This closes the claim that no isolated worker exists; it does not qualify core's
runner 32 or move native fixture execution into that sandbox. Core scheduling
was resumed on runner 32 without changing its security settings; runner 33 was
not retagged or relaxed. The native-specific work below remains necessary.

The existing runner32 manager was read back on 2026-11-10: instance executor,
capacity_per_instance=1, max_use_count=1, idle_count=0 and no external cache. That
prevents cross-job host/daemon reuse and supports the separate security-scans job.
The deployed native path still runs host subprocesses. No runner settings,
protected pipeline configuration or production activation were changed here.

Implemented opt-in confinement:
- native.py separates run_controller from candidate run; receipts and generated
  harness source live outside candidate writable roots. A protected configuration
  file plus independently selected digest are required; a configured failure has
  no host fallback. See scripts/architecture/CONFINEMENT.md for the exact contract.
- native_confinement.py creates one nonroot Docker container per command using an
  already-present digest-pinned image, private PID/IPC/network/cgroup namespaces,
  read-only root/source/policy/harness mounts, zero capabilities, seccomp filtering,
  no-new-privileges and explicit CPU/memory/PID caps. No Docker socket, controller
  HOME or receipt path is mounted. Environment values use an allowlist; Git clone
  credentials/hooks are removed. Candidate outputs remain writable separately.
- check.py keeps policy calculation in the controller and sends Cargo/cc/nm through
  that boundary. Cargo 1.98 supports separate harness lockfiles; harness compilation
  uses fresh target directories and a fresh copy of the immutable image Cargo seed.
  Source harnesses remain read-only. Candidate output paths are checked before use.
- Fixture container lifecycle is controller-only. Bounded fixed-destination Unix
  socket capabilities expose only controller-selected loopback fixture ports to
  loopback adapters inside the network-none candidate. No destination-routing
  protocol or general network proxy is supplied. Core's online 1.5.5 migration
  recorder is refused in confined mode until its inputs are collected separately.
- Artifact/JUnit intake rejects links, nonregular files, path escape and oversize;
  controller hashes the copied bytes after confirmed command/container disposal.

Actual 2026-11-10 evidence: an existing local Colima/runc Linux runtime and its
preinstalled Python image exercised nonroot execution, inaccessible controller
secrets/receipts, denied policy/source/rootfs writes, absent Docker socket and
CI/AWS credentials, denied metadata/external network, command failure, timeout
with a forked descendant, confirmed container removal and distinct controller/
candidate dispatch. Fixed-destination socket forwarding was exercised locally.
A separate actual Cargo 1.98 metadata fixture confirmed external lockfile placement.
These small fixtures do not prove a native build, TSan, a cross-namespace live
service roster, a deployed core runner, independent host attestation or a release.

Remaining engineering and deployment dependencies:
1. Build/pin and qualify an offline Linux native toolchain/dependency-seed image on
   existing infrastructure. Native worker readback confirms Docker/Python/Rust, but
   no compatible pinned image was verified. Qualify required TSan/personality and
   all fixture behavior under the selected runtime; do not weaken confinement to
   make a test pass. Worker filesystem quotas and the selected runtime's kernel/
   user-namespace boundary also need an explicit deployment policy.
2. Split the online pinned 1.5.5 migration recorder into protected input collection
   and confined execution. Migrate Docker-spawning conformance and external judge
   networking to controller capabilities, and register generated-project harness
   roots. These paths refuse explicitly in confined mode; legacy dev still works.
3. Deploy independent host observation, bind lifecycle/regular outputs to the actual
   source/artifact/config/image digests, then run the full final-vector native,
   conformance and release witnesses in CI. The producer still refuses absent or
   mismatched observations. Controller-self-reported fields are not that evidence.
4. Owner-approved signer/identity/key/log/registry authority and production routing
   remain separate prerequisites. No signing, registry publication or QA/main
   activation was performed.

Assurance language

A signature proves approved-key possession and payload integrity. Provenance
records a builder's claims about a build. An SBOM describes an inventory. Scanner
passes mean no findings under the named rules/database at that time. None is
proof of no vulnerabilities, correctness, reproducibility, complete SBOM closure,
independent audit or formal certification. Do not claim a SLSA Build level until
the deployed builder and provenance satisfy its assessed requirements; use
slsa_build_level: not-assessed meanwhile. SLSA schema v1 is not "SLSA level 1".
FIPS validates specified cryptographic modules/configurations, not a Rust project
or the presence of a KMS key; no FIPS/SOC2/ISO certification follows from this work.
[SLSA build requirements](https://slsa.dev/spec/v1.2/build-requirements)


Final-build inventory and OCI equivalence (implemented)

The producer emits busbar.release-inventory/3. Each native row additionally binds
its public build_closure file; the SBOM and its logged statement are derived from
that exact closure. Version 1/2 downloaded inventories remain readable for
compatibility and explicitly return build_closure_verified:false and
image_binary_equivalence_verified:false. New producer plans require version 2;
there is no producer fallback to an unmeasured SBOM.

scripts/release/cargo_capture.py wraps the final Cargo build in release-build.sh
and the final profile-use build in pgo-build.sh. The existing flags, manifest,
package, target and output directories are preserved. The capture adds Cargo's
JSON message format, snapshots locked metadata using the same target and feature
selection, and verifies that metadata and lock did not change during the build.
It keeps cargo-metadata.json, Cargo.lock and cargo-messages.jsonl under the private
build evidence directory. A compiler failure discards that capture; failed release
builds remove archives and closure files so a retry cannot reuse old evidence.

build_closure.py requires exactly one successful final build-finished message,
every reported compiler package in the locked metadata and Cargo.lock, and the
selected packaged binary among that build's compiler outputs. It hashes the actual
binary and every regular tar/ZIP archive member, rejecting links, traversal,
duplicate names and mismatched bytes. Its public busbar.build-closure/1 contains
source commit, target, release/component identity, artifact digest, member hashes,
compiled package inventory, actual emitted feature sets, dependency edges between
compiled packages, and digests of the private capture inputs. Local paths and
source URLs are not published; source identities are hashed. Registry package
checksums come from the exact lockfile. The producer recomputes this entire object
from independently pinned raw capture inputs before emitting a signing request.
A candidate-provided closure or candidate-selected digest alone is insufficient.

The CycloneDX scope is explicitly cargo-compilation-including-build-tools. This
includes the actual Cargo compilation packages (including procedural macros and
build tools), and does not pretend every one is linked into the runtime binary.
It does not enumerate an OS image or independently discover C libraries hidden
inside build scripts; runtime dependency contracts and per-platform image scans
remain necessary. A successful compilation stream is an observed compiler claim,
not a substitute for the independent native-controller boundary. The capture runs
inside that existing boundary and carries no signing authority.

candidate.py now consumes the final captures instead of resolving an unrelated
cargo-cyclonedx graph. It preserves the closure files when assembling slices and
uses the manifest-declared published native archive for images, matching the
current digest-pinned glibc Dockerfile. It emits both published-target and image
SBOM names where one native archive feeds both. No new image build path or native
platform exception is introduced.

For every v3 OCI platform the producer and independent download verifier rehash
the export and descriptor closure, verify configuration rootfs.diff_ids against
the decompressed layer bytes, and replay layers in memory without extracting paths.
Whiteouts and opaque-directory removal apply before each layer's additions;
replacement files, directories, symlinks and hardlinks cannot retain an earlier
matching binary. The final configured entrypoint must be the declared absolute
path, an executable regular file with exactly the native archive member's size
and SHA-256. Compressed layers currently support OCI/Docker gzip and uncompressed
tar; an unsupported codec refuses rather than skipping content verification.
The OCI statement includes native_member plus binary {path, size, sha256}.

Supported-release delivery monitoring (implemented; activation separate)

The existing rekor_watch.py entrypoint accepts the new protected catalog mode:

  python3 /trusted/release/rekor_watch.py \
    --catalog /trusted/supported-releases.json --catalog-sha256 <approved hash> \
    --scratch /existing/private/task-directory \
    --archive-root /existing/protected/release-archive \
    --result /protected/monitor-result.json

release_monitor.py requires schema busbar.release-monitor/1 with valid_until and
a nonempty releases list. Each release contains release, support_until,
inventory_sha256, trust: {path, sha256}, and files mapping every basename to
{url, sha256, size}. Use exact credential-free HTTPS URLs to approved existing
storage. The catalog is independently pinned and expires; missing/expired support
entries require explicit review, not an implicit silent deletion. The monitor
rejects redirects, unexpected encoding, credentials in URLs, missing files,
extra/mutated release bytes, invalid or absent log proofs, trust substitution and
OCI registry-attestation drift. Downloads have size and timeout bounds and no
retry/fallback loop. It verifies every v3 artifact/SBOM/OCI/inventory bundle using
the pinned trust, then records verified checkpoint-envelope hashes in the result.

An optional existing local archive root receives a new directory named by the
inventory digest, with exclusively created files, fsync and read-only permissions.
Existing directories must contain the complete identical byte set; no release is
overwritten or pruned. This is archive custody plus recurring delivery monitoring,
NOT provider-enforced WORM retention. Results deliberately expose
storage_retention_enforced:false and log_consistency_observed:false. Revalidating
signed inclusion checkpoints is not a consistency/gossip witness against a
current independently observed log head. No lifetime-locked storage backend or
independent checkpoint monitor was established by this session. Owner selection
and existing-provider policy readback are needed before making those claims.

ci/security/release-monitor.yml supplies the existing protected schedule include
interface. It is not included or activated by these source changes. Its catalog,
trust files, immutable tool directory and scratch location must be supplied by
the controller; a candidate dotenv or editable project variable is not authority.
Monitor results retain one year as job evidence; that job expiration is not the
supported lifetime of released bytes. No production log writes, signing, registry
attestation publication, QA/main activation or storage-account changes occur.

The issuer remains exactly https://github.com. GitLab signing identity
requirements above are unchanged: the approved local protected-main signing
configuration and its exact config SHA, numeric project identity, audience and
actual validated claims must be established before activation. A GitHub mirror,
GitHub Actions identity, or decoded-but-unverified JWT cannot fill those inputs.


Development qualification and release readiness
----------------------------------------------
The protected core controller uses ci-coverage.json's QA artifact-attestation and
main Sigstore stages. Only push/API pipelines on dev, or same-project merge
requests targeting dev, can receive busbar.development-conformance/1. It binds
the controller CI context, source and policy revision, raw invocation digest,
coverage digest and a fresh busbar.release-engineering/1 report. The report must
run all 60 pinned release engineering and stage regression checks with no skips,
using the protected offline Cosign/cryptography bundle. These include an actual
small locked Cargo build and Cosign offline positive/tamper controls; synthetic
keys and disabled log checks in those fixtures establish no production signing.

The common conformance wrapper stays unchanged. Its invocation exit1 and
slsa-verifier not-run verdict remain raw evidence. The controller permits only
the exact unattempted QA subject-absence reason, after every other required suite
passes. Failed signatures, attempted checks, incomplete evidence, collection
errors and engineering failures remain fatal. This legacy suite verifies a
ModernCI check-output attestation with Cosign; it is not upstream slsa-verifier
or proof of a SLSA level. Its currently unshipped producer binding remains visible.

Development observes absent Sigstore inputs as not-run; partially supplied or
malformed inputs fail. QA/main API evaluations require Sigstore inputs and never
receive this development classification. Consumers must validate the separate
controller classification and its bound engineering report while retaining the
raw failed driver step and unsigned/not-run release rows. Neither a green
development qualification nor these test fixtures activates a release signer.
