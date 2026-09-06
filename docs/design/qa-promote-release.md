# The qa/main release split: stage on `qa`, promote on `main`

Status: DESIGN + DRAFT IMPLEMENTATION (branch `design/qa-promote-split`, workflows drafted but not
yet exercised in CI). Owner review required before merge.

## The requirement, in the owner's words

> push to dev, fast builds and tests; push to qa, everything is done and tested; push to main and
> it just tags and releases what was built in qa. going to qa is identical PGO build just not
> finalized and pushed. we shouldn't be building again on main as that build is not technically
> what we QA'd. we repeat until 1.6.0 is perfect and qa green, then we push to main after X
> iterations.

Every sentence of that maps to a structural property below, not to a habit.

## What is wrong with the current shape

Today release.yml runs the whole pipeline — plan, gate, build all five binaries, stage the PGO
image under `staging-<sha12>`, verify everything, then promote — on the push to **main**. The
order inside the run is already right (nothing public until `verify-staged` is green; that design
and its 1.5.3 rationale are unchanged and untouched here). What is wrong is **when the bytes are
born**: on the main push. Everything that happened on `qa` — qa-gate's multi-hour plugin soak,
benchmarking, manual testing of the staged image — was evidence about a *different* build than the
one that ships. "The rebuild should be identical" is the exact reasoning this repository has paid
for twice already (the two-build-path release-key gap that shipped three broken aarch64 releases;
the 1.5.3-era rebuild-instead-of-retag). The fix is the same shape as those fixes: make the
identity structural. **One build, on `qa`. Main retags it.**

## The three branches after the split

| branch | trigger effect | cost | what a green run means |
| --- | --- | --- | --- |
| `dev` | ci.yml only (full tier on dev; fast tier on feature branches) | minutes | the code is healthy |
| `qa` | ci.yml + qa-gate.yml (unchanged) + **release-stage.yml (new)** | ~1h wall, real money | *everything* is built, verified, and recorded; the release exists, unnamed |
| `main` | **release.yml (now promote-only)** | seconds-to-minutes | the qa-built bytes now have their names |

### Push to `qa` — `release-stage.yml` (new file)

Runs the entire build-and-prove half that used to live in release.yml, verbatim where possible:

* `plan` — version read from Cargo.toml, refuse-if-already-released, Docker Hub immutability
  pre-flight, mint `staging-<sha12>`. Unchanged logic.
* `branch-green` — waits for **CI** on this exact sha, then proceeds. Deliberately scoped to the
  required workflow names only (unlike the promote's wait-for-everything gate), because qa-gate
  fires off CI's *completion* and soaks for hours: a wait-for-everything here deadlocks-by-timeout
  on every staging run, and putting qa-gate on an exception list would be a lie (it *is* a check of
  the commit). Nothing is lost: everything this workflow produces stays under throwaway names, and
  the wait-for-everything judgment — qa-gate umbrella included — is re-asserted on the *same sha*
  by release.yml before any name is minted.
* `gate` — fmt/clippy/build/test with the live pinned Postgres/Valkey services. Unchanged.
* `draft` — the GitHub Release created/reused as a **draft** anchored at the qa sha. One new
  behaviour: on reuse (iteration 2..N of the same version) the draft is **re-anchored**
  (`gh release edit --target <sha>`), because release.yml verifies the draft's target commitish
  against the sha being promoted.
* `targets` / `upload-assets` / `sbom` / `openapi` — all five platform binaries plus metadata
  built onto the draft. Unchanged.
* `stage-image` — docker.yml called with `staging_tag` + `label_version`: the mandatory-PGO,
  fail-closed, provenance-attested multi-arch build, pushed under `staging-<sha12>` only.
  Unchanged; this *is* the release image, minus its name.
* `verify-assets` / `verify-artifact` / `verify-set-equality` / `verify-staged` — every verifier,
  unchanged, including verify-deploy.yml in `staging` mode against the staged image and the
  draft's real downloadable bytes.
* `record-staged` (new) — writes the durable record (below). Gated on `verify-staged` by ordinary
  `needs:` semantics, so a red verification writes **no record** — fail-closed at the source.

"Push to qa, everything is done and tested" is therefore literal: when this workflow is green, the
release is *finished*. It has simply not been named.

### Push to `main` — `release.yml` (rewritten, promote-only)

* `plan` — same version read and pre-flights. A main push that cuts nothing (docs after a
  release) is still a safe no-op via `release=0`.
* `branch-green` — wait-for-everything on this sha, and the **required-present** set grows from
  `CI` to `CI, qa-gate, Release stage`. Because qa→main must be a fast-forward (below), main's
  HEAD *is* the qa commit those runs certified, so "we repeat until qa is green, then push to
  main" stops being a habit: a commit with no green qa-gate and no green stage run on record is
  refused before anything else happens. (The required-workflows presence loop was also fixed to
  split on commas — `Release stage` contains a space, and the old `for w in $VAR` word-splitting
  would have asserted the presence of workflows named `CI,qa-gate,Release` and `stage`.)
* `resolve-staged` (new) — **the seam**. Finds the successful `Release stage` run whose
  `head_sha` equals main's HEAD, downloads its `staged-manifest` record, and re-derives every
  claim in it from outside before anything irreversible happens:
  1. no successful stage run for this exact sha → **refuse** (the fast-forward contract's teeth);
  2. record artifact missing/expired → **refuse** (remedy: re-run the stage on the same sha —
     idempotent — never rebuild here);
  3. record internally inconsistent (sha/version/staging-tag/digest shape) → **refuse**;
  4. Docker Hub *and* GHCR must currently resolve `staging-<sha12>` to the recorded digest, read
     over the Distribution API the way `docker pull` reads it → **refuse** on any mismatch (the
     record has gone stale relative to the registry);
  5. `gh attestation verify` must pass on the staged image → **refuse** unattestable bytes;
  6. the draft must exist, still be a draft, be anchored to this sha, and carry assets →
     **refuse** otherwise.
  There is no fallback build anywhere in the file, and the new lint rule R10 makes reintroducing
  one a build failure.
* `promote-image` — docker.yml's existing manifest-only promote, fed
  `promote_from = <the record's staging tag>`. Bit-identical bytes, attestation carries over,
  seconds not minutes, idempotent — all pre-existing properties of the primitive, now applied
  across the branch boundary instead of within one run.
* `promote-release` — unchanged: promote-time red-recheck, push the git tag at this sha, flip the
  qa-built draft to published+latest, re-derive all four facts from outside.
* `notify-downstream` / `discord-notify` / `consumer-verification` — unchanged.

A failure anywhere up to and including `resolve-staged` leaves what it always left: no git tag, no
listed release, no `X.Y.Z` container tag, no fan-out (`release-order-lint.py --prove` re-verified
against the new graph). What changed is the retry price: recovery after a red promote no longer
re-spends the ~40-minute PGO build, because the promote never contained one.

### The fast-forward contract

Promote by fast-forwarding qa to main: `git push origin qa:main` (or a fast-forward merge). This
is the one operating-procedure change the split asks of a human, and it is self-enforcing rather
than documented-only: a merge commit, a direct push to main, or a cherry-pick mints a sha that no
stage run certified, so `branch-green` finds no `Release stage`/`qa-gate` runs for it and
`resolve-staged` finds no record — both refuse, with messages that say "fast-forward a green qa
commit". Consequence worth stating: **everything that lands on main must ride through qa**,
including docs-only changes (cheap: they stage, they promote as a no-op if the version is already
released). A GitHub branch-protection rule requiring linear history on `main` would make the
contract visible at push time instead of at workflow time; recommended, but it is belt-and-braces
— the workflows fail closed without it.

## The durable record: workflow artifact, not a committed manifest

`record-staged` writes `staged.json`:

```json
{
  "version":     "1.6.0",
  "tag":         "v1.6.0",
  "rc_tag":      "v1.6.0-rc.1",
  "qa_sha":      "<full sha>",
  "staging_tag": "staging-<sha12>",
  "digest":      "sha256:…",
  "run_id":      "<stage run id>",
  "recorded_at": "2026-08-27T…Z"
}
```

uploaded as the `staged-manifest` artifact of the stage run (90-day retention, GitHub's ceiling),
after re-deriving that the registry currently serves exactly that digest under exactly that tag.

Both options were weighed:

**Committed manifest file** (workflow commits e.g. `.release/staged.json` to `qa`):
* *For*: the record travels with the git history; readable with `git show`; no API dependency and
  no expiry at promote time.
* *Against, and decisive*: a workflow that commits to `qa` mints a **new sha**, so the record can
  only ever certify the *parent* of the commit it rides on — the record and the thing recorded can
  never name each other, and "the commit main promotes" and "the commit qa verified" permanently
  differ by one bot commit. It also: races concurrent qa pushes (non-fast-forward push failures in
  the workflow); requires `contents: write` on the staging pipeline; makes the "verified digest" a
  thing a human can edit in a PR, which converts a derived fact into an assertable one — the exact
  claim-without-assertion shape verify-deploy's header warns about; and pollutes qa (and, via
  fast-forward, main and every tag) with one machine commit per iteration.

**Workflow artifact + Actions-API lookup by head sha** (chosen):
* *For*: the binding "this record ↔ this commit ↔ this green, verification-gated run" is asserted
  by the Actions API (`head_sha`, `conclusion=success`) and by artifact ownership — not claimed by
  file contents. Zero extra commits, zero races (each run owns its artifact), and the record is
  only writable by a stage run that reached `record-staged`, i.e. one whose `verify-staged` passed.
* *Against, accepted because both failure modes fail closed*: artifact expiry (90 days) and API
  unavailability at promote time both surface as a **refusal** in `resolve-staged` with a
  one-command remedy (re-run the stage on the same sha — idempotent, re-records the same digest),
  never as a guess or a fallback build.

The tie-breaker is the repository's own precedent: receipts over claims (`verify-artifact`'s
receipt artifacts, `verify-set-equality` reading receipts rather than job conclusions). The
artifact **is** a receipt; a committed file is a claim.

## Release candidates: one record, two names

The first 1.6.0 ships as `v1.6.0-rc.1`, soaks, and then ships as `v1.6.0` — **the same bytes both
times.** That is a naming decision, so it lives entirely on the naming side of the split; nothing
about the build, the verification or the record's provenance changes.

### Where the rc name comes from

**From `crates/busbar/Cargo.toml`'s version plus an rc counter, supplied as a `release_tag` input
on the staging dispatch.** Both halves matter:

* The **version** is still Cargo.toml's, and only Cargo.toml's. `plan` refuses any `release_tag`
  that is not exactly `v<that version>-rc.<N>`. There is no second place a version can come from,
  which is why a free-text `RELEASE_TAG` was rejected: it would let a dispatch stage bytes under a
  name that the OCI version label, the CHANGELOG section and the committed OpenAPI document on that
  sha all contradict — and every downstream check reads those, not the input.
* The **counter** is typed by a human, once, and recorded — it is not derived from "how many rc
  tags exist" at run time. The record is read up to 90 days later by a different workflow, so a
  name computed from the tag namespace at staging time would be a claim about a different instant
  than the one it is used in. `prepare-release.yml` already models the version as an explicit
  dispatch input for exactly this reason: naming a release is a decision, recorded, not recomputed.

An ordinary push to `qa` supplies no input, so `rc_tag` is `""` and the staging path is
bit-for-bit what it has always been.

### How one record names both tags

`staged.json` carries two name fields, and says which is which:

| field | value | what minting it does |
| --- | --- | --- |
| `tag` | `v1.6.0` — always present | the RELEASE. Publishes the draft, moves `latest` and `armv8.0`, pushes the git tag, fans out, announces, runs the public consumer sweep. |
| `rc_tag` | `v1.6.0-rc.1`, or `""` | the CANDIDATE. Pushes the git tag and the immutable image pins `1.6.0-rc.1` / `1.6.0-rc.1-armv8.0` — and nothing else. The draft stays a draft, `latest` does not move, no repo is told, nothing is announced. |

They describe the **same** `digest`, `compat_digest` and `assets`, because there is only one build.
The record is keyed by `qa_sha`, and a sha may wear more than one name over its life; what the
record adds is that the set of names it may ever wear is **closed at two, and written down on qa**.
`resolve-staged` refuses any `release_tag` that is not one of those two strings, so "two tags, one
record" can never widen into "any tag, one record".

### Who mints which, and when

* **Push to `main`** — mints `rc_tag` if the record offers one and that rc tag does not exist yet;
  otherwise mints `tag`. For a record with no rc this is exactly the pre-existing behaviour.
* **`workflow_dispatch` of `Release` with `release_tag: v1.6.0`** — the second promotion of the
  same record, after the soak. No rebuild, same digest, same draft.
* **`workflow_dispatch` with `release_tag: v1.6.0-rc.2`** — only if the record names it.

The irreversible name is therefore never a side effect of a push while a candidate is pending: a
Docker Hub `1.6.0` cannot be un-published, so it is minted by an explicit human act once the soak
has said something. The candidate, which moves no floating pointer and publishes nothing, is what
the push mints.

`docker.yml`'s promote gains one input for this, `promote_latest` (default `true`): a candidate
mints the immutable pins and leaves the floating pointers alone, and the job's landing assertion
asserts exactly the names it was asked to move — asserting `latest == 1.6.0-rc.1` would be
asserting a falsehood about a correct run, and asserting nothing would drop the 1.5.3 guard.

## The marketing site is observed, never depended on

The site deploy is **not** part of the release path (owner, 2026-09-06). `GetBusbar/marketing` was
on `.github/release-notify-targets.txt`, so every release dispatched `upstream-release` to it —
which is what triggers its deploy, and `notify-downstream` fails outright if any single dispatch
fails, with `consumer-verification` hanging off it. A marketing-side token, rename or outage could
therefore turn an already-published, perfectly good busbar release red. It has been removed from
that list. The site keeps its own trigger (its push-to-main deploy plus its daily poll of busbar's
`/releases/latest`), which is what makes it self-healing without being wired into this path.
Nothing in this repository triggers, `needs:` or waits on the site deploy, and nothing under the
site's content directory (which lives in that other repo) is touched.

The site's state is still **observed**: verify-deploy's checks (g)/P6/(k)/(n) read `getbusbar.com`
after publication, from `consumer-verification`, which by construction runs only once the release
is already public. They can report; they cannot gate. (They are also skipped entirely after a
candidate promote, where nothing public moved and a "the site does not advertise 1.6.0-rc.1" red
would be a fabrication.)

## Benchmarking prices the QA binary — literally

The staged image under `staging-<sha12>` (better: pinned by the record's digest) is the artifact
every benchmark, soak, or pricing run should pull during the qa window. Because the promote is a
manifest-only retag re-verified against the recorded digest, the numbers measured on qa are
numbers about the exact bytes users pull as `X.Y.Z` — not about a sibling build "that should
match". A benchmarking workflow slots in as a consumer of the stage run (e.g. `workflow_run` on
`Release stage`, or a job appended after `verify-staged`), reads the digest from `staged-manifest`,
and — if its verdict should gate the release — simply needs to be a named workflow that concludes
red on this sha: release.yml's promote-time branch-green refuses red *and* unknown without any
further wiring. (Adding it to `REQUIRED_WORKFLOWS` is the stricter option once it exists; a name
listed there must be *present* for the sha, not merely not-red.)

## The iteration loop

Each qa push is a full iteration: fresh sha → fresh `staging-<sha12>` on both registries → fresh
digest → fresh record on a fresh stage run → the one shared draft per version re-filled
(`--clobber`) and re-anchored to the new sha. Nothing accumulates state that a later iteration
must clean up for correctness: the promote looks up the record **by main's HEAD sha**, so exactly
the iteration that is fast-forwarded to main can resolve, and every earlier record, tag, and
digest is unreachable by construction. Two consequences named rather than discovered:

* **Stale staging tags accumulate** on Docker Hub and GHCR (`staging-*` is mutable, so a re-run of
  one sha overwrites in place, but distinct iterations are distinct tags). Harmless to
  correctness; a periodic cleanup sweep is a deliberate separate chore, never part of a release
  path that must stay idempotent.
* **The draft's assets always describe the latest staged iteration**, and `resolve-staged` proves
  it (target-commitish check) rather than assuming it.

## Rotating the oracle golden — the step that follows every `vX.Y.Z` tag on main

**The golden is always the last shipped binary; the register is always this release's named
differences.** Both halves are invariants, and neither is self-maintaining.

The shadow oracle's entire claim is "this build behaves like the last *shipped* one". That claim
decays at the instant `promote-release` succeeds: from then on every ci.yml `shadow-oracle` run and
every qa-gate `done-oracle` run is still measuring the distance to the release *before* the one
users are now pulling. The second half decays with it, and more quietly:
`testing/shadow-oracle/accepted-differences.json` is cumulative, every entry is a permanent
blindfold over the surface it names, and nobody ever removes one — removing an entry *looks* like
weakening a gate, when in fact the difference has shipped and is no longer a difference at all. Left
alone, a 1.6.0→1.6.1 regression hides behind a register written about 1.5.5.

So, immediately after the tag is pushed and the draft is published:

```
testing/shadow-oracle/rotate-golden.sh <version> --dry-run   # read the plan; changes nothing
testing/shadow-oracle/rotate-golden.sh <version>             # land it as one commit on dev
```

What it does, and the order is load-bearing:

1. Reads the published release assets' sha256 digests from the GitHub release **by tag**, read-only
   (`gh release view <tag> --json assets,isDraft`). The digests are GitHub's own record of the
   uploaded bytes — never a hash of a local download, which would pin whatever the network handed
   this machine.
2. **Refuses** if any required digest is missing (the four platform archives plus the openapi
   document), and refuses a **draft** outright. A draft's assets are re-uploadable in place, so a
   digest read from one pins a *name*, not the bytes — and under this split the draft is full of
   every asset for the whole qa soak before it is published. An absent pin is RED, never permission
   to pin fewer assets: that is `fetch-golden.sh`'s own rule, one level up.
3. Appends the rows to `golden-digests.tsv` **before** recording, because that file is inside the
   `harness_rev` set (`harness-rev.sh`): recording first would stamp the golden with a revision that
   stops existing one line later, and `diff-cells.py` would refuse the very recording just made.
4. Fetches the new golden by that pin and records it with the existing `record.sh --plane all`,
   landing it through `merge-recordings.py` — the merge/replace path — so provenance is asserted by
   **sha** (version + `binary_sha256` + `host_triple`), not by the path someone typed.
5. Archives the outgoing register at
   `testing/shadow-oracle/golden/<old-version>/accepted-differences.json` and resets
   `accepted-differences.json` to an empty register (rules kept, entries cleared). The archive is
   what makes the reset a rotation rather than a loss.
6. Re-stamps `harness_rev` over the final tree and asserts the new golden carries exactly it.

It deliberately does **not** rewrite the version literals in `ci.yml`, `qa-gate.yml` or
`verify-1.6.0-done.sh` — those are the workflow graph and the done claim, and a `sed` across them
from inside a data-rotation script is how a release procedure silently becomes a workflow edit. It
greps and prints them as the remaining one-line, reviewable changes.

`--selftest` drives every refusal over fake release JSON (missing archive, digest-less asset, empty
release, a complete set on a draft, an already-pinned version, a malformed version, and a proof that
`--dry-run` leaves `golden-digests.tsv` byte-identical), so the rules are proven to fire on a laptop
with no release in existence.

**The reminder is a run summary, not an issue.** `promote-release` ends with a post-release
checklist step that renders this chore into `$GITHUB_STEP_SUMMARY` on the promote run that created
the obligation — with the exact two commands — and does nothing else. It does not run the rotation
(that re-records ~885 cells and resets a register: owner judgements that land as a reviewable
commit, not side effects of a promote that has already made everything public), and it is not an
issue, because `scripts/no-self-filed-issues-lint.sh` forbids this repository from writing into its
own tracker. A candidate promote prints nothing: an rc moves no floating pointer and is not what
users pull, so it is not "the last shipped binary".

## Exactly which files change

| file | change |
| --- | --- |
| `.github/workflows/release-stage.yml` | **new** — the build/verify/record half, on push to `qa`. Body is release.yml's jobs verbatim except: header, trigger, `branch-green` rescoped to required-names-only (with the deadlock rationale in place), draft re-anchoring on reuse, and `record-staged` replacing the five promote/notify jobs. |
| `.github/workflows/release.yml` | **rewritten** — promote-only, on push to `main`. Keeps `plan`, `branch-green` (required set now `CI, qa-gate, Release stage`; comma-safe presence loop), the two promote jobs, fan-out, Discord, `consumer-verification`. Gains `resolve-staged`. Loses every build/verify job (moved, not deleted). |
| `.github/workflows/docker.yml` | comment-only: header now names release-stage.yml as the staging caller and release.yml as the promote caller. No behavioural change; still no tag trigger. |
| `.github/workflows/prepare-release.yml` | comment-only: the branch-model paragraph (which still described tag-on-main.yml) now describes the split. |
| `.github/workflows/ci.yml`, `qa-gate.yml`, `verify-deploy.yml` | **unchanged.** dev/fast-tier behaviour, the qa soak, and both verify modes already fit the split. |
| `scripts/release-order-lint.py` | rules follow the jobs: R3/R5 now assert against release-stage.yml; R4 gains both halves of the seam (promotes ⟵ `resolve-staged`; `record-staged` ⟵ `verify-staged`); R9 covers both files' gates and both trigger blocks; **R10 (new): main never rebuilds, qa never names** (no build-workflow call, PGO script, image build, or `staging_tag:` handoff in release.yml; no `promote_to:` handoff or `--draft=false` in release-stage.yml). Mutations re-anchored; `--selftest` proves all 17 red; `--prove` re-verified over the new graph. |
| `scripts/ci-images.py` | the service-pin agreement check follows the `gate` job: compares ci.yml against release-stage.yml. Selftest re-anchored. |

All repo lints pass on this branch: `release-order-lint.py` (check, `--selftest`, `--prove`),
`ci-images.py` (`--list`, `--selftest`), `structure-lint.sh`, `release-script-lint.sh`,
`no-self-filed-issues-lint.sh`, `qa-gate-dispatch-lint.py`.

## Open questions for the owner

1. **Branch protection on `main`** — turn on "require linear history" (and optionally restrict
   pushes) so a non-fast-forward promote is refused at push time rather than by a red workflow?
   The workflows fail closed either way.
2. **Docs-only pushes to main** — under the fast-forward contract they must ride through qa (and
   spend a full staging run). Acceptable, or should qa-worthy vs. trivial changes get a cheaper
   path? (Any cheaper path re-opens "main has commits qa never saw"; recommendation: accept the
   cost, it preserves the invariant.)
3. **Should the benchmark be a required gate?** Once the benchmarking workflow exists and runs per
   stage run, adding its name to release.yml's `REQUIRED_WORKFLOWS` makes "benchmarked" a
   precondition of "released". Say the word and it is one line.
4. **Staging-tag cleanup cadence** — `staging-*` tags accumulate one per iteration on both
   registries. Monthly sweep in monthly-refresh.yml, or leave them?
5. **`workflow_dispatch` of Release stage on non-qa refs** — currently possible (useful for
   rehearsal); its artifacts are only consumable if that sha later becomes main's HEAD. Restrict
   the dispatch to `qa`, or keep the flexibility?
6. **Record retention** — 90 days is GitHub's ceiling. If more than 90 days ever elapse between
   the final qa push and the main push, the promote refuses and asks for one idempotent stage
   re-run. Fine, or should the record additionally be mirrored somewhere non-expiring (which
   re-opens the committed-manifest tradeoffs)?
