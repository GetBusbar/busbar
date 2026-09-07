# The release path — how a release actually happens (and where the workflows do not yet do it)

The contract, in the owner's words:

> "dev is fast, qa is build and real testing, when qa is green it's prod ready and we just tag it
> and move it to main and release, but the qa build is what we release."

This page is three things: the runbook a human follows, the evidence that the workflows do (or do
not) implement the sentence above, and the branch-protection settings the sentence implies. It
changes no workflow. Every fix below is written to be dispatched separately.

---

## 1. The runbook

Everything runs from a clean checkout of `GetBusbar/busbar`. Nothing here tags by hand — the tag is
an OUTPUT of a green run, never an input.

### 1.1 Prepare the version (on `dev`)

Write the notes under `## [Unreleased]` in `CHANGELOG.md`, push to `dev`, then:

```
gh workflow run prepare-release.yml --repo GetBusbar/busbar --ref dev -f version=1.6.0
```

That bumps `crates/busbar/Cargo.toml` + `Cargo.lock`, regenerates the committed OpenAPI schema,
rolls `[Unreleased]` → `[1.6.0]` with today's date, and pushes to `dev`. It does not tag.

### 1.2 Push to qa

```
git fetch origin
git push origin dev:qa            # fast-forward only; never a merge commit
```

### 1.3 Wait for qa green

"qa green" means three workflow runs are green **on the exact qa HEAD sha**:

```
QA=$(git rev-parse origin/qa)
gh run list --repo GetBusbar/busbar --commit "$QA" \
  --json name,status,conclusion,url --jq '.[] | "\(.name)\t\(.status)/\(.conclusion)"'
```

You are waiting for all three of:

| workflow | what it proves |
|---|---|
| `CI` | fmt, clippy, build, the full-tier gate, the shadow oracle, the proof manifest |
| `qa-gate` | the ~2 h all-plugins end-to-end soak against real backends |
| `Release stage` | the ONE build: 6 binaries + SBOM + OpenAPI onto a draft, the PGO image under `staging-<sha12>`, every verifier, and the `staged-manifest` record |

Watch the expensive one directly:

```
gh run watch --repo GetBusbar/busbar \
  "$(gh run list --repo GetBusbar/busbar -w 'Release stage' -b qa -L1 --json databaseId --jq '.[0].databaseId')"
```

Iterate on `qa` as many times as it takes. Every push re-stages: fresh sha, fresh
`staging-<sha12>`, fresh digest, fresh record, the same draft re-filled and re-anchored. Only the
iteration you fast-forward to `main` can ever ship.

### 1.4 Benchmark / soak the thing that will actually ship

```
docker pull getbusbar/busbar:staging-$(git rev-parse --short=12 origin/qa)
```

The promote is a manifest-only retag, so numbers measured here are numbers about the bytes that
ship.

### 1.5 Push to main (this is the release)

```
git push origin qa:main           # fast-forward only
```

There is nothing else to do. `release.yml` reads the version from `Cargo.toml`, refuses if the
commit on `main` is not the staged qa sha, retags the recorded digest as `X.Y.Z` + `latest`, pushes
the git tag `v1.6.0`, publishes the qa-built draft, and fans out.

### 1.5-rc The 1.6.0 path: candidate first, release after the soak

1.6.0 does not go straight to `v1.6.0`. It goes `v1.6.0-rc.1`, soaks, then `v1.6.0` — **from the
same staged bytes, with no second build.** Three commands, in this order:

```
# 1. On qa, stage the candidate name onto the sha that is already staged and green.
gh workflow run "Release stage" --repo GetBusbar/busbar --ref qa -f release_tag=v1.6.0-rc.1

# 2. Fast-forward. The push mints the CANDIDATE, not the release, because the record offers an
#    rc that has not been minted yet.
git push origin qa:main

# 3. After the soak, on the same sha, mint the release from the same record.
gh workflow run Release --repo GetBusbar/busbar --ref main -f release_tag=v1.6.0
```

Step 1 costs a full staging run (~40 minutes, the two-arch PGO build is the long pole), and that
cost is named rather than engineered away. The rc name is a property of the **record**, and the
record is written by a staging run; deriving it later, at promote time, from "how many rc tags
exist right now" would make the name a function of the tag namespace at an instant up to 90 days
after the bytes were proved — a different fact than the one the record is for. `resolve-staged`
takes the newest successful stage run for the sha, so this re-stage supersedes the earlier record
for the same commit and the digest it proves is the digest it promotes.

What step 2 mints: the git tag `v1.6.0-rc.1` and the immutable image pins
`getbusbar/busbar:1.6.0-rc.1` (+ `-armv8.0`) on both registries. What it does **not** touch:
`latest`, the `armv8.0` floating pointer, the draft release (it stays a draft), the downstream
fan-out, Discord, and the public consumer sweep. `docker pull getbusbar/busbar` keeps serving 1.5.x
for the whole soak. Soak testers pull `getbusbar/busbar:1.6.0-rc.1`; for binaries,
`gh release download v1.6.0` works against the draft (a draft's assets are downloadable by tag
through the API, which is what makes the draft a real artifact before it is a public one).

Step 3 is a second promotion of the **same record**: same digest, same draft, same attestation, no
compiler. It publishes the draft, moves `latest`, pushes `v1.6.0`, and fans out.

A second candidate is `v1.6.0-rc.2` — never `rc.1` again. Both the git tag and the Docker Hub pin
are immutable, and `plan` refuses a taken rc name before spending the build.

**Why step 3 is a human act.** `1.6.0` on Docker Hub can never be overwritten, so the irreversible
name is minted by an explicit dispatch after the soak has said something, not as a side effect of a
push. The push mints only the reversible candidate.

### 1.6 Watch the release

```
gh run watch --repo GetBusbar/busbar \
  "$(gh run list --repo GetBusbar/busbar -w Release -b main -L1 --json databaseId --jq '.[0].databaseId')"
```

If anything before `promote-image` fails: no git tag, no listed release, no `X.Y.Z` container tag,
no fan-out, `latest` has not moved. Re-run the workflow; every step is idempotent. **Never** "just
rebuild it on main" — that is the one move the whole split exists to ban.

---

## 2. What the workflows actually do, with evidence

### (1) Does `release-stage` on qa build ONCE and stage by sha with digests?

**Yes for the image. Partially for the binaries.**

- One build pipeline, no per-target `if:`, everything a target needs arrives as a matrix value:
  `.github/workflows/build-artifact.yml:79-148`, matrix emitted from the single manifest at
  `.github/workflows/release-stage.yml:657-724` reading `.github/release-targets.json`.
- The image is built once and pushed under `staging-<sha12>` only:
  `.github/workflows/release-stage.yml:803-815` → `.github/workflows/docker.yml:571-720`.
- The record is written only on green and only from re-derived facts, and it carries the manifest
  digests: `.github/workflows/release-stage.yml:1169-1236`. It refuses on an empty digest
  (`:1189-1196`) and refuses unless the registry already serves that digest for the staging tag
  (`:1197-1212`).
- **The record carries no binary digests.** `staged.json` is
  `{version, tag, qa_sha, staging_tag, digest, compat_digest, run_id, recorded_at}`
  (`.github/workflows/release-stage.yml:1213-1215`). The per-artifact SHA-256 exists — the build
  writes it (`scripts/release-build.sh:185-189`, uploaded as `build-evidence-<target>`) and the
  contract binds it to the downloaded bytes (`.github/artifact-contract.json:156-169`) — but it
  never reaches the record, so nothing on `main` re-proves it. See gap 4.

### (2) Does `release` on main promote without rebuilding, and refuse a non-staged sha?

**Yes, and yes — this half is solid.**

- No build of any kind on main is possible: `scripts/release-order-lint.py:393-429` (rule R10)
  fails CI if `release.yml` contains `build-artifact.yml`, `pgo-build`,
  `docker/build-push-action` or `cargo build`, or if any job passes `staging_tag:` to
  `docker.yml`. Wired into CI at `.github/workflows/ci.yml:145,147,164` inside `structure-lint`,
  which is a scored row of `ci umbrella` (`.github/workflows/ci.yml:1639`). Runs clean on HEAD.
- The promote is a manifest-only retag of the recorded digest:
  `.github/workflows/release.yml:576-592` → `.github/workflows/docker.yml:159-290`.
- The refusal is by head sha, not by a claim in a file: the staged run is looked up as a successful
  `Release stage` run whose `head_sha` is exactly `main`'s HEAD
  (`.github/workflows/release.yml:447-451`), and the record's `qa_sha` must equal it
  (`.github/workflows/release.yml:475`). A merge commit, a direct commit to main or a cherry-pick
  has no such run and is refused with no fallback build.
- The record is then re-derived from outside before anything irreversible: registry tag→digest on
  BOTH registries (`.github/workflows/release.yml:502-524`), `gh attestation verify` on both
  staged images (`:530-537`), and the draft must exist, still be a draft, be anchored to this sha
  and carry assets (`:544-552`).

### (3) Is the artifact set identical to 1.5.5's, and signed?

Published `v1.5.5` (from `gh release view`) carried **7** assets:

```
busbar-x86_64-unknown-linux-gnu.tar.gz    busbar-aarch64-unknown-linux-gnu.tar.gz
busbar-x86_64-apple-darwin.tar.gz         busbar-aarch64-apple-darwin.tar.gz
busbar-x86_64-pc-windows-msvc.zip
busbar-openapi-v1.5.5.json                busbar-v1.5.5.cdx.json
```

1.6.0 will publish **8**: the same seven plus `busbar-aarch64-unknown-linux-gnu-armv8.0.tar.gz`,
the armv8.0 baseline arm64 build declared at `.github/release-targets.json` (the
`aarch64-unknown-linux-gnu-armv8.0` entry). The set is derived from that one manifest and enforced
by name, not by count, at `.github/workflows/release-stage.yml:827-905` (`verify-assets`) and as
set equality declared==built==verified at `:1029-1090`.

- **No plugin tarballs, deliberately.** busbar's release publishes only the core artifacts; every
  first-party plugin releases from its own repo. Stated at
  `.github/workflows/release-stage.yml:770-792`, and confirmed by 1.5.5's asset list. So "plugin
  tarballs in the artifact set" is not a gap — it is the current design.
- **The Docker image is not a release asset**; it is registry tags
  (`getbusbar/busbar:X.Y.Z`, `latest`, `X.Y.Z-armv8.0`, `armv8.0`, on Docker Hub and GHCR),
  minted only by `.github/workflows/docker.yml:159-290`.
- **Signing, stated precisely.** The release *key* (`BUSBAR_RELEASE_PUBKEY`) is not a signature
  over busbar's own artifacts — it is the ed25519 PUBLIC half compiled into the binary so a
  first-party *plugin* signature verifies. The busbar artifacts are signed by
  Sigstore/OIDC build provenance (`.github/workflows/build-artifact.yml:125-128`) and, for the
  image, cosign on GHCR plus attestations on both registries
  (`.github/workflows/docker.yml:722-765`).
- The release key IS enforced, on both ends, for every target:
  input side `scripts/release-build.sh:96-113` (refuses to compile without a well-formed 64-hex
  key), output side the `release_pubkey` and `first_party_plugin` contract rows
  (`.github/artifact-contract.json:70-107`, implemented at `scripts/verify-artifact.py:255,279`),
  asserted against the bytes downloaded back from the draft on the target's own native runner
  (`.github/workflows/release-stage.yml:932-1000`).
- **`scripts/release-key-guard.sh` has no callers.** See gap 3.
- The one plugin tarball this repo still packs (headroom, baked into the image) is fail-OPEN when
  `BUSBAR_SIGN_KEY` is unset: `.github/workflows/docker.yml:534-537`. A fix is landing separately;
  it is listed here for completeness only.

### (4) What "qa green" means mechanically

- `release-stage`'s own gate waits only for the **`CI`** workflow on the sha:
  `REQUIRED_WORKFLOWS: "CI"` at `.github/workflows/release-stage.yml:243`. It deliberately does
  NOT wait for `qa-gate` — `qa-gate` fires off CI's completion and soaks for hours, so waiting
  would deadlock (`:217-227`). So **staging happens before the qa soak concludes**, which is fine:
  everything it produces stays under a throwaway name.
- The full-population judgment is on the main push:
  `REQUIRED_WORKFLOWS: "CI,qa-gate,Release stage"` at `.github/workflows/release.yml:249`, present
  AND green, with `NOT_COMMIT_CHECKS: "Release,Verify deploy"` (`:293`), unknown-is-red, no waiver
  (`:224-396`), and re-asserted immediately before the tag is minted (`:630-657`).
- `qa-gate`'s own single verdict is the `qa-gate umbrella` job, which counts `skipped` as red
  (`.github/workflows/qa-gate.yml:319-351`).
- **But the promote-time judgment of `qa-gate` is currently maskable.** See gap 1.

### (5) How the tag is applied, and what is checked against it

- Applied by `release.yml`'s `promote-release` job, not by a human:
  `git tag -a "$TAG" -m "$TAG" "$SHA" && git push origin "$TAG"` at
  `.github/workflows/release.yml:658-679`, as `Matthew Jackson <matthew@pq.io>` (`:674-675`),
  with the default `GITHUB_TOKEN`. Existing tag at the same sha is a no-op; at a different sha it
  REFUSES rather than moving the tag (`:669-672`).
- Version source is `crates/busbar/Cargo.toml`, shape-checked `X.Y.Z`
  (`.github/workflows/release.yml:127-129`), and the tag is literally `v$VERSION` (`:132`).
- `--version` **is** checked against it: the `version_anchored` contract row, anchored on both ends,
  executed on the shipped bytes on a native runner
  (`.github/artifact-contract.json:109-120`, `scripts/verify-artifact.py:339`).
- The OCI image version label is checked the same way (`image_version_anchored`,
  `.github/artifact-contract.json:212`).
- **CHANGELOG is NOT checked against the tag.** See gap 5.
- Immutability pre-flight refuses before anything is built if `getbusbar/busbar:X.Y.Z` (or
  `X.Y.Z-armv8.0`) already exists on Docker Hub: `.github/workflows/release.yml:155-181` and
  `.github/workflows/release-stage.yml:160-173`.

### (6) Anything that would make the main artifact differ from the qa artifact

Nothing on `main` rebuilds — R10 makes that structural (see (2)). Within the qa stage:

- **Toolchain**: pinned in one place, `rust-toolchain.toml` (`channel = "1.98.0"`), and every
  release-path job names the same pin: `.github/workflows/release-stage.yml:437,590,608`,
  `.github/workflows/build-artifact.yml:86`, `.github/workflows/docker.yml:335`. (`qa-gate.yml`
  uses `@stable` at `:184,212,254,292`, but its cargo invocations run inside the repo, where the
  toolchain file wins — it is a soak, not a producer of shipped bytes.)
- **Build date**: nothing embeds one. `crates/busbar/build.rs:84-90` stamps profile, opt-level,
  target, target-cpu, target-features and LTO only. No `vergen`, no `SOURCE_DATE_EPOCH` need.
- **Cargo features**: the release binary is `-p busbar` with default features; the `openapi-schema`
  feature is CI-only and used only to emit the OpenAPI asset
  (`.github/workflows/release-stage.yml:628`), never in the shipped binary.
- **Lockfile**: see gap 6 — the release build does **not** pass `--locked`.

---

## 3. Gap list

Each gap: what the workflows do, where, the fix, and whether it is code or settings.

### Gap 1 — a red `qa-gate` on the qa sha can be masked at promote time (code)

`.github/workflows/release.yml:328` filters the run list with `| unique_by(.name)`. jq's
`unique_by` keeps exactly ONE element per key, and the Actions API returns runs newest-first, so
the newest run of each workflow name wins. On a main push, CI runs again on the same sha, its
completion spawns a **second** `qa-gate` run whose jobs all skip — and that run is NEWER than the
real qa-push one. `skipped` is counted green at `.github/workflows/release.yml:358-362`. So the
qa soak's actual verdict is discarded in favour of the empty one.

The comment at `.github/workflows/release.yml:246-248` asserts the opposite
("unique_by(.name) sees red if either is red"); that claim is false. Verified:
`echo '[{"name":"qa-gate","conclusion":"skipped"},{"name":"qa-gate","conclusion":"failure"}]' | jq -c 'unique_by(.name)'`
→ `[{"name":"qa-gate","conclusion":"skipped"}]`.

The same masking applies to the `present` assertion at `:350-356`: a skipped run satisfies it.

**Fix (code):** stop collapsing to one run per name. Judge EVERY run on the sha (drop
`unique_by`), or, if de-duplication is wanted, keep the WORST conclusion per name rather than the
newest — and stop treating `skipped` as green for the names in `REQUIRED_WORKFLOWS` (a required
workflow that skipped has not run). Correct the comment at `:246-248` in the same change.

### Gap 2 — `ci.yml`'s `proof-manifest` pushes a commit to `qa`/`main` (code)

`.github/workflows/ci.yml:1258-1329`. The job runs on pushes to `main`, `dev` and `qa` (`:1260`)
and ends with `git commit … [skip ci]` + `git push origin "HEAD:${VERSION}"` (`:1316-1329`, where
`VERSION` is `github.ref_name`, i.e. the branch). Two independent problems on the release branches:

- `qa` and `main` are protected with required status checks and `enforce_admins: true` (verified
  live via `gh api repos/GetBusbar/busbar/branches/{qa,main}/protection`). A push of a commit that
  carries none of those statuses is rejected → the job fails → the `CI` run concludes failure →
  `release-stage`'s gate 0 (`.github/workflows/release-stage.yml:243,304-309`) REFUSES to stage.
  This blocks the release outright.
- If it ever did succeed, it would mint a NEW qa HEAD carrying `[skip ci]`, so no `CI`, no
  `qa-gate` and no `Release stage` run would exist for it. Fast-forwarding that sha to `main` is
  then refused by `resolve-staged` (`.github/workflows/release.yml:447-451`) — a release that
  cannot be cut, caused by CI itself.

`docs/proof/` currently holds only `dev.json` and `index.json`, consistent with this never having
been exercised on a protected branch.

**Fix (code):** restrict the commit-back step to `dev` only, and on `qa`/`main` publish the
manifest as a run artifact (and/or let the release pick it up), never as a commit. Alternative:
generate `qa.json`/`main.json` on `dev` and let them ride the promotion like every other file.

### Gap 3 — `scripts/release-key-guard.sh` is dead code (code)

Zero callers anywhere in `scripts/` or `.github/` (grep). Its `require` half is re-implemented
inline at `scripts/release-build.sh:96-113`; its `assert-embedded` half is re-implemented as the
`release_pubkey` contract row (`.github/artifact-contract.json:70-86`,
`scripts/verify-artifact.py:255`). Coverage is real, but the named guard is orphaned, so it is
never exercised and will drift from the two copies that matter.

**Fix (code):** either call it (`scripts/release-build.sh` invokes `release-key-guard.sh require`
before the build, and the contract row shells out to `assert-embedded`), or delete it and point
its documentation at the two live implementations. Do not leave a guard nobody runs.

### Gap 4 — the staged record does not pin the draft's binaries (code)

`.github/workflows/release-stage.yml:1213-1215` records only image digests.
`.github/workflows/release.yml:544-552` re-checks the draft is a draft, is anchored to this sha and
has `assets > 0` — but not WHICH assets, and not their digests. Between the stage and the promote
(potentially 90 days, per the retention note at `:1232-1236`) an asset could be deleted, replaced
or added and the promote would publish it. The image half of the record is rigorously re-derived;
the binary half is not.

**Fix (code):** add `assets: [{name, size, sha256}]` to `staged.json` (the digests already exist in
`build-evidence-<target>/artifact.sha256`), and have `resolve-staged` assert set equality of names
and re-download-and-hash, or at minimum assert the exact name set from
`.github/release-targets.json` plus per-asset size. Fail closed on any difference.

### Gap 5 — nothing checks the CHANGELOG has a section for the version being tagged (code)

The release body extraction is explicitly fail-soft: `.github/workflows/release-stage.yml:515-542`
warns and falls back to generated notes when no `## [X.Y.Z]` section exists.
`scripts/changelog-lint.py` (wired at `.github/workflows/ci.yml:174,176`) checks the SHAPE of the
top entry (version + date, ordering, no future dates) but never that a section exists for the
version in `crates/busbar/Cargo.toml`. So `v1.6.0` can be tagged and published with a release body
that does not say what changed.

**Fix (code):** add a rule to `changelog-lint.py` — on `qa` and `main`, the newest released heading
must be `## [<Cargo.toml version>], <date>`. That makes the version, the tag, the `--version` line
and the CHANGELOG one fact instead of four.

### Gap 6 — the release binary build does not pass `--locked` (code)

`scripts/release-build.sh:175` and `scripts/pgo-build.sh:182,533` all run plain
`cargo build --release`. The comment at `scripts/release-build.sh:146-147` says the lockfile
freshness gate is `gate`'s job — and `gate` does run `cargo build --workspace --locked`
(`.github/workflows/release-stage.yml:445-447`) — but that is a different job on a different
runner. Nothing stops the shipped binary's build from re-resolving if the lockfile drifts between
the two, and the failure would be silent.

**Fix (code):** pass `--locked` on every release build invocation. It is free when the lockfile is
fresh and is a hard refusal when it is not, which is the property wanted on the bytes that ship.

### Gap 7 — `qa` requires a status check that cannot exist on the sha being pushed (settings)

`qa`'s required contexts are `["ci umbrella","qa-gate umbrella"]` (verified live). `qa-gate` only
runs off a CI completion on `qa` (`.github/workflows/qa-gate.yml:87-89,138-141`), so a dev sha
never carries a `qa-gate umbrella` status. With `enforce_admins: true`, `git push origin dev:qa` —
step 1.2 of the runbook — is rejected for a check that by construction cannot be green yet.

**Fix (settings):** `qa` requires `ci umbrella` only. `qa-gate umbrella` belongs on `main`, where
it CAN be green on the sha being pushed. See §4.

### Gap 8 — `RELEASE.md` documents the pre-split release (docs)

`RELEASE.md:9` still says a push to `main` runs "the whole release … build, stage, verify, THEN
tag", and `RELEASE.md:35-64` narrates `release.yml` doing `gate`, `draft`, `build + attach`,
`stage-image` and `verify-staged` on the main push. All of that moved to `release-stage.yml` on the
qa push, and `scripts/release-order-lint.py` R10 now forbids it on main. `RELEASE.md:9` also names
`qa-gate.yml` as the only thing a qa push runs, omitting `Release stage` — the expensive one.

**Fix (docs):** rewrite `RELEASE.md` around this page's §1 and §2, or replace it with a pointer
here. A runbook that describes a shape the linter forbids is worse than none.

### Gap 9 — `main` does not require the stage to have happened (settings)

`main` requires `ci umbrella` and `qa-gate umbrella`. Both can be green on a sha that was never
staged; the refusal in that case comes only from `resolve-staged`
(`.github/workflows/release.yml:447-451`), i.e. after the push has landed on the release branch.
Cheap belt-and-braces: require the stage's terminal job too, so a non-staged sha cannot reach
`main` at all.

**Fix (settings):** add `record the staged digest (the promote's only input)` to `main`'s required
contexts. See §4.

---

## 4. Required status checks, per branch

Current state, read live from `gh api repos/GetBusbar/busbar/branches/<b>/protection`:

| branch | required contexts today | `enforce_admins` | linear history |
|---|---|---|---|
| `dev` | none | true | true |
| `qa` | `ci umbrella`, `qa-gate umbrella` | true | — |
| `main` | `ci umbrella`, `qa-gate umbrella` | true | true |

What they should be, given that every promotion is a fast-forward push and a required check must
therefore already be green on the sha being pushed:

| branch | required contexts | why |
|---|---|---|
| `dev` | *(none)* | "dev is fast". Optionally `ci umbrella` on PRs into dev; never on direct pushes. |
| `qa` | `ci umbrella` | The only context a `dev` sha can carry. Removing `qa-gate umbrella` here is gap 7. |
| `main` | `ci umbrella`, `qa-gate umbrella`, `record the staged digest (the promote's only input)` | All three run on the qa sha and are green before the fast-forward. Together they mean: the code passed CI, the plugin soak passed, and the bytes were built, verified and recorded. |

Keep on both `qa` and `main`: `enforce_admins: true`, `required_linear_history: true`,
`allow_force_pushes: false`, `allow_deletions: false`. Linear history is what makes "main's HEAD IS
the qa commit" true, which is the entire trust model of `resolve-staged`.

These are settings changes; they are not made by this document.

---

## 5. Summary against the owner's sentence

| the sentence | state |
|---|---|
| "dev is fast" | holds — `ci.yml` only, no required checks on dev |
| "qa is build and real testing" | holds — `Release stage` builds every byte once on the qa push; `qa-gate` soaks against every plugin |
| "when qa is green it's prod ready" | holds mechanically at promote time (`REQUIRED_WORKFLOWS: "CI,qa-gate,Release stage"`), **except** gap 1, which can mask a red `qa-gate`, and gap 2, which can prevent qa from going green at all |
| "we just tag it and move it to main" | inverted, deliberately and correctly: you move it to main and the workflow tags. Nobody tags by hand. |
| "the qa build is what we release" | holds for the image (manifest-only retag of the recorded digest, enforced by R10) and mostly for the binaries (the draft is qa-built and re-anchored), **except** gap 4: the promote does not re-prove which binaries are on the draft |
