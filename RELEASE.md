# Releasing Busbar

The branch ladder is **dev → qa → main** (predev is retired, OWNER 2026-10-16: lanes land on
`dev`), and ModernCI judges and moves every rung from this repository's branch files (OWNER
2026-10-12, "ModernCI only"; the ruling is
[`docs/design/BUSBAR-1.6.0.md`](docs/design/BUSBAR-1.6.0.md) Part 6, "BUSBAR-RELEASE RETIRED FROM
BUSBAR"). A branch file is named for the branch being moved and says what the move must pass.

| Move | Branch file | What it runs | Consent |
|---|---|---|---|
| a `lane-*` branch into **`dev`** | [`.ci/default.yaml`](.ci/default.yaml) | preflight, every registered gate, clippy, compile, test, doctest, deletion matrix, `cargo deny`, the gated suites; no worse than dev (required check `ci`) | none |
| **`dev`** into **`qa`** | [`.ci/dev.yaml`](.ci/dev.yaml) | the gates, the oracle against the 1.5.5 golden, conformance, `scripts/verify-1.6.0-done.sh`, the Q128 audit, the gated suites; all absolute | the owner's approval (the org ruleset keeps `qa` locked) |
| **`qa`** into **`main`** | `.ci/qa.yaml` (on ModernCI's `modernci-config` branch) | the five checks, plus `candidate`: every release artifact built once, kept, never rebuilt. It holds no key and publishes nothing | the owner. Then the owner's publish run (below) |

## Publishing (the owner's run, with his hardware keys)

ModernCI builds; the owner signs and publishes. No signing key exists in CI. The design is
`PUBLISH-PIPELINE-1.6.0` (security docs); how users check the result is [`docs/verify.md`](docs/verify.md).

The owner works in **his own clone at the release commit**, with `busbar-plugin-pack` built there by
him:

```
cargo build --release -p busbar-plugin-loader --features pack --bin busbar-plugin-pack
modernci call artifact --check candidate ...            # the judged candidate's outputs -> ./candidate
# The signed version tag (G-15), with K2 at the release commit, then on GitHub (touch the key):
git -c gpg.format=ssh -c user.signingkey=<sk handle> tag -s v<V> -m "busbar <V>" <release commit>
git -c gpg.ssh.allowedSignersFile="$PWD/release/allowed_signers" verify-tag v<V>
git push <GitHub remote of GetBusbar/busbar> v<V>
G=scripts/release/publish_gate.py; T=~/.config/busbar-release/trust.json; P=target/release/busbar-plugin-pack
python3 $G verify --candidate candidate --trust $T --pack $P --out out    # every rule; nothing signed
python3 $G sign   --candidate candidate --trust $T --pack $P --out out --k1-sign-cmd <release signer cmd> --k2-key <sk handle>
python3 $G upload --candidate candidate --trust $T --pack $P --out out    # draft, Rekor, publish, verify, then latest
```

`verify` refuses, one named line per rule, on:
- a version tag `v<V>` that is missing, lightweight, unsigned, not signed by K2 under the `git`
  namespace (`release/allowed_signers` carries the K2 key once more, limited to `namespaces="git"`),
  or not at the release commit (G-15); `upload` also refuses unless GitHub holds that same tag
  object, and creates the release on it (`gh release create --verify-tag`);
- any missing or undeclared artifact, `plugin-index.json` included (the release index
  `busbar --migrate-config` fetches from this release; `candidate.py assemble` renders it and the
  gate refuses any other bytes);
- a digest mismatch;
- a plugin tarball that is not an unsigned first-party build (`sign` then seals every plugin with ONE
  release-manifest signature and refuses any tarball that does not verify through the chain to the
  compiled-in roots: docs/design/release-trust.md);
- a key list that differs from the owner's trust file;
- a binary without the embedded key;
- an image whose binary is not the built one;
- a version already published.

`sign` shows the full commit and the key-list diff before any key is touched. `upload` moves `latest`
only after downloading the release back and verifying it as a user would. A plugin released between
core releases is pinned in `release/plugin-pins.tsv`. The `candidate-plugins-<target>` checks build
it unsigned, and the owner runs `publish_gate.py plugin-release <repo> <tag> --plugins <slices>`.
Nothing runs on GitHub Actions. The
busbar-release hop (`promote.yml`, the engine pin) is deleted and no move is decided by it.
busbar-release remains the tools repo: the home of the oracle (`busbar-oracle`, pinned by
the branch file's `BUSBAR_ORACLE_*` env and fetched from its `dev-bin` release by `bin/oracle`), the
soak and the plugin fleet generator. The 1.5.5 golden the oracle reads stays in this tree, in
`testing/shadow-oracle/golden/1.5.5`.

**The tag is an OUTPUT of a green release, never an input.** The only `v*` tag is the one the owner
signs with K2 in the publish run above, at the judged candidate's commit; no workflow is
triggered by a `v*` tag (`cargo xtask gate workflow-rules`, rule R1). Docker Hub tag immutability
makes a published `X.Y.Z` impossible to overwrite, so a broken one is permanent.

## The one human step

Write your notes under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) (Keep-a-Changelog
headings: Added / Changed / Fixed / Security). `cargo xtask gate changelog --require-version=X.Y.Z`
**refuses** a version whose section is missing or is not the newest entry in the file.

## Preparing a version (on `dev`)

```
python3 .github/scripts/bump_cargo.py 1.6.0 crates/busbar/Cargo.toml
cargo update -p busbar --precise 1.6.0
UPDATE_OPENAPI=1 cargo test -p busbar -p busbar-kernel -p busbar-core-admin --features openapi-schema openapi_json_matches_committed_file
python3 .github/scripts/roll_changelog.py 1.6.0 CHANGELOG.md
```

That bumps `crates/busbar/Cargo.toml` + `Cargo.lock`, regenerates the committed OpenAPI schema, and
rolls `[Unreleased]` to `[1.6.0]` with today's date. It does **not** tag. Land it on `dev` like
any other change; it reaches `qa` with the next promotion.

## Moving a version up the ladder

ModernCI opens and judges each promotion (`modernci call moves` shows how each stands). A red move
is fixed forward on the lower branch: every push re-judges it on the new head.

## Branch protection this assumes

`dev` requires ModernCI's check `ci`; `qa` and `main` take the owner's consent (the org ruleset).

Branch protection lives in repository rulesets, not in a script (see `.github/required-status-checks.md`).
Keep `enforce_admins: true`, `required_linear_history: true`, `allow_force_pushes: false` and
`allow_deletions: false` on `qa` and `main`. No workflow may push a commit to either branch
(`workflow-rules` R11).

The ruling: [`docs/design/BUSBAR-1.6.0.md`](docs/design/BUSBAR-1.6.0.md) Part 6, the release engine.

## Downstream (self-healing, no action needed)

- **Homebrew** — the tap's `bump-formula` workflow runs daily and updates both `busbar` and
  `busbar-admin` formulae (version + checksums) when it sees a newer release. A missed run just
  catches up the next day.
- **Website** — the download page shows the new version automatically (`src/release.json` is
  regenerated from Cargo at build). For the version-**pin** examples (docker/compose/helm/attestation),
  run `node scripts/bump-site-version.mjs X.Y.Z` in the marketing repo and push — or wire a
  Cloudflare Pages deploy hook to rebuild on release. *(This never touches `facts.ts BUSBAR_VERSION`,
  which stamps measured benchmark data and only changes on a re-benchmark.)*
- **SDKs** (`busbar-python` / `-js` / `-go`, `busbar-admin`) — these carry their own semver and
  regenerate from `openapi.json`; tag them (`vX.Y.Z`) only when you want to publish a new SDK cut.
  Publishing is tokenless (OIDC / git tag).

## Honesty invariant

Every performance number the site publishes is stamped with version + hardware + source, enforced
by a build-time self-check in `facts.ts` that fails the build if a stamp is missing. Re-benchmark →
update the measured value **and** its `BUSBAR_VERSION`/hardware stamp together; never bump the stamp
without a real run behind it.
