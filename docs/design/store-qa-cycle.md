# The durable-store QA cycle

How busbar proves its four durable store backends — **sqlite, postgres, mysql, valkey** — against the
shadow oracle and the plugin functional probes, on a repeatable schedule, for as long as the stores
ship.

Tracker row **A8** ("oracle coverage: postgres / mysql / valkey store-persist cells (services)") is
the first instance of this cycle, not the whole of it. A8 is one recording. The question this
document answers is the one behind it: *what is the standing loop that keeps these four backends
proven, run after run, release after release, without anyone remembering to do it?*

The short version: **a store backend is proven when a real busbar binary has dlopened the real
published plugin, written through it to a real server, been killed, restarted against the same
server, and read the money back.** Everything below is machinery for making that sentence true on a
schedule and impossible to quietly stop being true.

---

## 0. Where the cycle stands today (the measured starting point)

Facts, all verified against the tree at `origin/integration/oracle-phase0`.

**The oracle owns four store-persist cells** (`testing/shadow-oracle/cells.json:30190-30247`):

| cell id | golden verdict | why |
|---|---|---|
| `plugins.store-persist\|store-sqlite` | **PASS** (`golden/1.5.5/ledger.tsv:2197`) | needs no server |
| `plugins.store-persist\|store-postgres` | **SKIP** (`ledger.tsv:2176`) | `needs_fixture: true` |
| `plugins.store-persist\|store-mysql` | **SKIP** (`ledger.tsv:2175`) | `needs_fixture: true` |
| `plugins.store-persist\|store-valkey` | **SKIP** (`ledger.tsv:2177`) | `needs_fixture: true` |

The SKIP text is the literal `named gap: the fixture this cell needs is not in the tree yet`. Three
of the four backends have **no persistence proof at all** in the oracle. The four sibling
`plugins.load|store-*` cells (`cells.json:30120-30174`) all PASS on the golden
(`ledger.tsv:2170-2173`) — so *loading* every published store is already proven; only *persisting*
through three of them is not.

**Why they SKIP, precisely.** `record.sh:397-399` short-circuits on `needs_fixture` **before** any
driver dispatch:

```
if [ "$(jq -r '.needs_fixture // false' <<<"$cell")" = true ]; then
  record "$id" SKIP "UNSUPPORTED: …" "named gap: the fixture this cell needs is not in the tree yet"; continue
```

So standing a postgres server next to the recorder changes nothing on its own. The flag must come
off the cell.

**And the script would not work if it did.** `scripts/store-persist.sh:28`:

```
[ -n "$SETTINGS" ] || case "$alias_" in sqlite) SETTINGS="{ db_path: \"${W}/governance.db\" }" ;; *) SETTINGS="{}" ;; esac
```

`{}` is the empty settings map. `store-postgres` and `store-valkey` both require a `url` key
(`docs/configuration.md:653-657`); `store-mysql` requires an equivalent and **has no documented
settings schema anywhere in `docs/`** — it is named as a published plugin at `docs/plugins.md:560`
and given a row in no configuration table. The cells would fail at `--validate` (step 1), not
persist-check.

**Ports do not collide, and that is not an accident to be preserved carelessly.** The oracle derives
its ports in a tight band: `record.sh:47` (`48811`/`48812`/`48781`), script cells at
`record.sh:415-417` (`SCRIPT_MOCK_PORT="$((ADMIN_PORT+1))"` = `48813`), boot cells at
`record.sh:207-208` (`48821`/`48822`), and `store-persist.sh:23`'s own fallbacks (`48831`/`48832`/
`48791`). Backend servers live at `5432`/`3306`/`6379` (GitHub `services:`) or `15432`/`13306`/
`16379` (`scripts/release-check.sh:1502,1524,1545` — deliberately offset so a developer's own
postgres is not disturbed). **The two bands are disjoint and must stay disjoint.**

**The provisioning already exists — in four places that disagree.**

| where | postgres | mysql | valkey | pinned? |
|---|---|---|---|---|
| `ci.yml` job `check` `services:` (`:332-370`) | yes `:349` | **no** | yes `:363` | by digest |
| `ci.yml` job `coverage` `services:` (`:1130-1152`) | yes | **no** | yes | by digest |
| `release-stage.yml` job `gate` `services:` (`:374-431`) | yes `:391` | **no** | yes `:415` | by digest + Docker Hub `credentials:` |
| `plugin-ci.yml` job `build-test-signoff` (`:136-220`) | yes `:155` | **yes** `:178` | yes `:165` | by digest |
| `scripts/release-check.sh` (`:1492-1590`) | yes `:1502` | yes `:1524` | yes `:1545` | **floating tags** |

The digests match across the four workflows (`postgres:16@sha256:9520…4b0b`,
`valkey/valkey:8@sha256:495e…8df6`, `mysql:8@sha256:b3b9…d3fb`). `release-check.sh` — the script the
**qa gate** runs — uses `postgres:16`, `mysql:8`, `valkey/valkey:8`, `hashicorp/vault` untagged. The
qa gate is therefore not pinned to the bytes CI is pinned to. The DSN spellings drift too:
`redis://localhost:6379/0` (`plugin-ci.yml:311`), `redis://localhost:6379` (`ci.yml:401,1166`),
`redis://127.0.0.1:16379` (`release-check.sh:1558`).

**The functional probe is complete and has never been wired to a backend.**
`testing/fleet-fixtures/probe-store.sh` does the whole job — validate, boot, mint, spend, assert the
body marker, read usage, **kill**, restart, assert the key and counters survived, drive one more
request (`:175-208`). It is parameterised by `STORE_MODULE`/`STORE_SETTINGS` (`:32-33`), so it
already accepts postgres/mysql/valkey. Its caller `.github/workflows/plugin-functional.yml` has
**no `services:` block at all**, and — critically — **no workflow in this repo calls it.** It is
invoked only from the plugin repos' own `functional.yml`. Inside busbar, `probe-store.sh` runs
nowhere.

**The conformance suite exists and is 3/9 wired.**
`crates/plugin-testkit/src/store_conformance.rs` publishes nine `assert_*` checks (`:125`, `:175`,
`:197`, `:230`, `:444`, `:486`, `:510`, `:533`, `:577`). The only caller in the workspace is
`crates/store-memory/tests/store_conformance.rs`, which runs **three** of them against an in-RAM
`MemoryStore`. The five plane-record checks and the duplicate-`seq` audit check run against **no
backend, anywhere**. The suite takes `&dyn Store` — an already-open in-process handle — so today it
cannot reach a dlopened plugin at all.

**The ABI window is `[2, 4]`.** `crates/plugin-loader/src/registry.rs:55` maps `"store"` to
`[STORE_ABI_FLOOR, busbar_plugin::cold::ABI_VERSION]` = `[2, 4]`
(`registry.rs:36`, `crates/busbar-plugin/src/cold/mod.rs:153`); the check is
`crates/plugin-sign/src/lib.rs:607-623`. All four **published** stores are ABI 2
(`docs/plugins.md:123-127`). `crates/store-example-plugin` packs at ABI 4 through the SDK
(`crates/plugin-sdk/src/lib.rs:63-64`). `crates/plugin-loader/src/store_adapter.rs:98` defines
`STORE_ABI_WITH_NEW_OPS = 5`, so **nothing loadable today speaks the new ops** — the ABI-2 adapter
path is the only path any published store takes, and it is the path the money regression that
tracker row B12 records was found on.

**There is no docker compose file in the repo.** `find` for `docker-compose*` / `compose*.y*ml`
returns nothing. Developers and unattended agents have no one-command way to stand these backends up.

---

## 1. Goals and the bar

### 1.1 What "green" means for a store backend

A store's entire job is that state survives the process. So the bar is stated once, in the language
the probes already use:

> A busbar binary loaded the real plugin, wrote through it, **died**, came back against the same
> server, and the key and its money were still there — and one more request went out through the
> restarted lane.

Three independent instruments say it, and none of them can be satisfied by the other two:

| instrument | what it proves that the others do not |
|---|---|
| **oracle cell** `plugins.store-persist\|store-<b>` | that **1.6.0 behaves byte-identically to published 1.5.5** through this backend. Compares `usage_after_restart`, `chat_after_restart`, `store_errors` and the survived verdict between two binaries (`scripts/store-persist.sh:104,111`). |
| **functional probe** `probe-store.sh <alias>` | that a **shipped artifact pair** (released busbar × released plugin tarball) works, independent of the monorepo tree. It asserts a body marker byte-for-byte and non-zero counters, so a store that answers 200 while persisting nothing is red (`probe-store.sh:160-172`). |
| **`store_conformance`** | that the four backends **agree with each other** on the trait's edge rulings — tombstone resurrection, unknown-id deletes, duplicate `seq`. The suite exists precisely because the fleet was found disagreeing (`store_conformance.rs:6-15`). Divergence here is invisible to both the oracle (one backend at a time) and the probe (happy path). |

### 1.2 The bar per stage

| stage | trigger | store bar | blocking? |
|---|---|---|---|
| **dev PR** | `pull_request` | oracle `plugins.store-persist\|store-sqlite` + `plugins.load\|store-*` (as today), plus **postgres** store-persist. The fast subset. | yes — via `shadow-oracle` in `ci-umbrella` (`ci.yml:1644`) |
| **dev merge** (push to `dev`) | FULL tier (`ci.yml:79-88`) | all four store-persist cells + `store_conformance` against all four live backends | yes |
| **nightly** | schedule | the full matrix of §5: 4 backends × 2 busbar refs × the ABI window | red opens/updates an issue; does not block a merge |
| **qa** (push to `qa`) | `qa-gate.yml` → `scripts/release-check.sh` | `phase-1-<alias>-binary` for **all four** backends (today: sqlite only, `release-check.sh:1401`) + every `phase-2-suite-store-*` | yes — `qa-gate umbrella` (`qa-gate.yml:319`) |
| **release-stage** (staging from `qa`) | `release-stage.yml` | the `gate` job's live services (`:374`) **plus mysql**, and the functional probes against the **staged** artifacts for all four backends | yes — `branch-green` + `verify-staged` |
| **main / release** | `release.yml` | nothing re-derived. `REQUIRED_WORKFLOWS: "CI,qa-gate,Release stage"` (`release.yml:249`) is consumed, per the CI-health doc's rule that one gate runs once and every later stage attests the earlier one (`docs/design/CI-HEALTH-2026-09-04.md:42-43,64-66`). | yes |

### 1.3 Tied to the oracle's own semantics

The oracle has exactly three dispositions and this cycle adds no fourth:

- **owed** — the golden recorded a PASS for this cell, so the candidate must too. `owed-baseline.txt`
  is the owed set as of the last sign-off (890 ids; `plugins.store-persist|store-sqlite` at `:865`).
  A cell that leaves the owed set is **RED** unless `accepted-gaps.json` names it with an owner
  (`replay.sh:19-25`). `accepted.accepted` is `[]` today — nothing has ever been knowingly dropped.
- **accepted** — a real behaviour difference, registered line-precisely in
  `accepted-differences.json` with a changelog line.
- **diverging** — anything else. Zero tolerated.

Coverage **growing** needs no entry and is simply printed (`accepted-gaps.json:_comment`). So turning
the three SKIP rows into owed rows is *always allowed*; what this cycle must guarantee is that
having grown, they can never silently shrink back. That guarantee is `owed-baseline.txt`: **the
re-record is not finished until the baseline names all four store-persist ids.**

### 1.4 The ship gate

A backend that cannot be provisioned is **not** a pass and **not** a soft skip on a promotion branch.
On dev PR / dev merge / qa / release-stage, a missing service is a **hard red** — the same discipline
`ci.yml:327-331` already states for the postgres/valkey roundtrip tests ("HARD-FAIL rather than
silently skip if a service is misconfigured — so this coverage cannot vanish unnoticed") and the
same one `verdict.sh` enforces with *zero rows is red*.

---

## 2. Service provisioning per stage

### 2.1 One pinned image list, four consumers

The drift table in §0 is the whole problem: five provisioners, four agreeing digests, one on floating
tags. Fix it the way the oracle already fixes artifact drift — **one pinned file, everything reads
it**, mirroring `testing/shadow-oracle/golden-digests.tsv` and `plugin-digests.tsv`:

```
testing/fleet-fixtures/service-images.tsv
# service  image                 digest                     ready-probe                                     port
postgres   postgres:16           sha256:9520…4b0b           pg_isready -U busbar                            5432
mysql      mysql:8               sha256:b3b9…d3fb           mysqladmin ping -h localhost -ubusbar -pbusbar  3306
valkey     valkey/valkey:8       sha256:495e…8df6           valkey-cli ping                                 6379
vault      hashicorp/vault       sha256:5be4…e1a2           wget -qO- http://127.0.0.1:8200/v1/sys/health   8200
```

- `ci.yml`, `release-stage.yml` and `plugin-ci.yml` keep literal `image:` lines (Actions cannot read a
  file into a `services:` block), but a new lint step — the same shape as the existing
  `plugin-registry-check.sh` — asserts every `image:` in `.github/workflows/` matches this file.
  A digest bump then lands in one commit and the lint proves the fan-out is complete.
- `scripts/release-check.sh` and the local helper (§2.3) **read the file directly**, which closes the
  qa-gate's floating-tag hole.
- Re-pinning: `docker buildx imagetools inspect <tag>` (`ci.yml:336`, `release-stage.yml:387`). The
  natural home is `monthly-refresh.yml` — which today only runs `cargo update`
  (`monthly-refresh.yml:31`) and never touches an image pin.

### 2.2 GitHub Actions — `services:` per stage

| job | add | rationale |
|---|---|---|
| `ci.yml` → `check` | **mysql** | the only gap; postgres and valkey have been there since 1.5.0 and mysql never was, which is why `BUSBAR_TEST_MYSQL_URL` is set nowhere in `ci.yml` |
| `ci.yml` → `shadow-oracle` | **postgres, mysql, valkey** | the store-persist cells run inside this job (`record.sh` drives them at `:407-424`) |
| `release-stage.yml` → `gate` | **mysql** | mirrors `check` (`:364-367` says so explicitly) |
| `ci.yml` → `coverage` | **mysql** | non-gating, but a coverage number that excludes a backend is a misleading one |

No `credentials:` on `ci.yml` (fork PRs are handed empty secrets — the reasoning at `ci.yml:339-347`
stands and is not weakened here). `release-stage.yml` keeps its authenticated pulls (`:400-402`); it
never runs on `pull_request`.

### 2.3 Local docker for developers and unattended agents

New: `testing/fleet-fixtures/store-services.sh` — the missing one-command path. No compose file: the
repo has none, `release-check.sh` already proves `docker run -d --rm` + a `docker exec` readiness
probe + an EXIT-trap teardown works, and a compose file would be a fifth source of truth for images.

```
store-services.sh up   [postgres|mysql|valkey|all]   # docker run from service-images.tsv, wait ready
store-services.sh url  postgres                       # print the DSN on stdout, nothing else
store-services.sh down [all]                          # remove containers; idempotent
store-services.sh ns   postgres <token>               # create + print a per-run namespace DSN
```

Contract:
- **Offset ports**, exactly `release-check.sh`'s: `15432`, `13306`, `16379`. A developer's own
  postgres on `5432` is never touched, and the oracle's `487xx`/`488xx` band is never approached.
- **Readiness is proven, not slept on**: `pg_isready` / `mysqladmin ping` / `valkey-cli ping` inside
  the container, with the caps `release-check.sh` measured — 60 s for postgres and valkey, **120 s**
  for mysql, whose first boot initialises the datadir and restarts once (`release-check.sh:1531-1533`).
- Containers named `busbar-store-qa-<svc>-$$`, `--rm`, registered for an EXIT trap.
- `down` is safe to run when nothing is up.

### 2.4 Credentials: ephemeral, never committed, never echoed

Four rules, and the third is the one with teeth.

**(a) The DSN is never in a checked-in file.** `cells.json` is committed, so it must not carry a URL.
It carries a **SecretRef** instead — a shape the store settings map already supports:
`docs/plugins.md:645-652` says any key in a plugin's `settings:` may be a `SecretRef` resolved by the
core *before the settings cross the ABI*, and an unresolvable ref fails load closed. So:

```jsonc
// cells.json, plugins.store-persist|store-postgres
"script": { "name": "store-persist.sh",
            "args": ["store-postgres", "{ url: { env: BUSBAR_ORACLE_STORE_URL_POSTGRES } }"] }
```

The literal `{ env: … }` is what is committed. The DSN itself lives only in the process environment.

**(b) In CI the DSN is a literal-in-workflow, not a secret.** `postgres://busbar:busbar@localhost:5432/…`
against a container that exists for eight minutes is not a credential; treating it as one buys
nothing and costs fork PRs their coverage. It stays in the workflow env exactly as
`ci.yml:400-401` has it today. **No production DSN is ever configured for any of these jobs**, and no
job reads a repository secret to build one.

**(c) The DSN must not leak into the recording.** This is a live hazard, not a hypothetical.
`scripts/store-persist.sh:78` records the last 300 bytes of the `--validate` log into the cell's own
effects:

```
step validate_tail "$(tail -c 300 "$W/validate.log" | tr '\n' ' ')"
```

and that value is normalized into `cells/<id>.json` (`record.sh:419`), which for a golden is
**committed to the repository**. A connection failure whose message quotes the URL would put
`user:password@host` into git history. The fix belongs in the script, before the value is recorded:
a `redact()` that rewrites `<scheme>://<user>:<pass>@` to `<scheme>://<REDACTED>@` and any bare
`password=`/`PGPASSWORD=` token, applied to `validate_tail` and to every `fail` body. Red-proof it by
recording a cell against a deliberately-wrong DSN and asserting the credential is absent from
`cells/…json`.

**(d) Nothing is echoed.** `store-services.sh url` prints to stdout for command substitution and
never logs; the workflow step that exports it uses `>> "$GITHUB_ENV"`, never `echo`. `set -x` is not
used in any store path.

### 2.5 Namespacing — the concurrency hazard the oracle creates

The shadow-oracle job records the golden **and** the candidate in the same job against the same
services (`ci.yml:1405-1415`). Postgres and mysql are shared, non-reset databases — the exact
condition `store_conformance.rs:17-28` documents. Two recordings writing the same `keys` table would
make each other's failure, and worse, the *candidate* could read the *golden's* rows and appear to
persist when it did not.

So: **every recording gets its own namespace, derived and disposable.**

- postgres / mysql: a per-run **database**, `busbar_oracle_<token>`, created and dropped by
  `store-services.sh ns`. `token` = the recording's output directory basename plus the pid — golden
  and candidate get different ones by construction.
- valkey: a per-run **logical db index** (`redis://…/<n>`) plus a key prefix, and `FLUSHDB` on that
  index at teardown — never `FLUSHALL`.
- sqlite: unchanged; already per-cell under `$RAW/store-work` (`store-persist.sh:24`).

The namespace is created **before** `record.sh` starts and dropped after it exits, so a killed run
leaks at most one empty database, and a nightly sweep removes `busbar_oracle_*` older than a day.

### 2.6 Teardown

Three layers, because the failure that matters is a *survived* container answering the next run's
probe with someone else's data:

1. Actions `services:` — GitHub reaps them; nothing to do.
2. `store-services.sh` and `release-check.sh` — `--rm` plus a single EXIT trap over a
   `DOCKER_CONTAINERS` array (`release-check.sh`'s existing pattern).
3. The probes' own guard: `assert_port_free` before binding (`lib.sh:98-104`,
   `probe-store.sh:57-60`, `store-persist.sh:29`) — the check that exists because
   consumer-verify once "reported a bundle healthy that had exited 1" (`lib.sh:95-97`). It stays,
   and it is the reason a leaked container is a loud red rather than a false green.

---

## 3. What runs

### 3.1 (a) Re-recording the golden so the SKIP rows become owed

This is the A8 deliverable and the one irreversible step, so its provenance rules matter most.

**Inputs, all pinned.**
- Binary: published **1.5.5** by digest — `fetch-golden.sh`, pins in `golden-digests.tsv`
  (`busbar-x86_64-unknown-linux-gnu.tar.gz` = `6f8ab606…c8ac`), refusing any mismatch.
- Plugins: the published 1.5.5-era tarballs by digest — `fetch-plugin.sh:24-35`, pins in
  `plugin-digests.tsv`: **store-postgres v1.0.6**, **store-mysql v1.0.6**, **store-valkey v1.0.7**,
  store-sqlite v1.0.6, four triples each. `fetch-plugin.sh` exits 3 on a digest mismatch and deletes
  the download.
- Services: the digests in `service-images.tsv`.

**The change that makes the cells recordable** (three edits, one commit):
1. `cells.json` — drop `"needs_fixture": true` from the three cells (`:30202`, `:30217`, `:30246`).
2. `cells.json` — add the settings arg as a SecretRef (§2.4a) to each of the three.
3. `store-persist.sh` — when the named env var is unset, record
   `SKIP  UNSUPPORTED: no <backend> service configured` via the existing `status:-1` path
   (`store-persist.sh:25`, honoured at `record.sh:422`). A laptop without docker gets a **named gap**,
   never a forced pass and never a red; CI, where the var is always set, cannot take that path.

**How the recording is made.** Not by re-recording all 885 cells — that would put a whole new golden's
worth of churn into one commit and make the diff unreviewable. Use the mechanism the golden's own
history already used twice (`golden/1.5.5/meta.json.merged_from` shows `golden-a10b` and two
`golden-fix-…` parts):

```
record.sh --bin ~/.cache/busbar-oracle/1.5.5/busbar --plane all \
          --filter 'plugins\.store-persist\|store-(postgres|mysql|valkey)' \
          --out target/oracle/recordings/golden-store
merge-recordings.py --out target/oracle/recordings/golden-1.5.5-next \
                    testing/shadow-oracle/golden/1.5.5 target/oracle/recordings/golden-store
```

`merge-recordings.py` enforces exactly the rules this needs and refuses everything else
(`merge-recordings.py:21,39-42,56-57,66-67`):
- the five provenance fields **`binary`, `version`, `binary_sha256`, `harness_rev`, `host_triple`**
  must be identical across parts, so a part recorded by a different binary or a different harness
  **cannot** be merged;
- cell ids and files must be **disjoint**, so a re-record cannot silently overwrite an existing row;
- `merged_from` is appended with each part's name, count and timestamp, and `at` becomes the max.

Two consequences to plan around, both real:

- **`harness_rev` will change** — `harness-rev.sh` hashes `cells.json` among others, and this change
  edits `cells.json`. So the existing 885 rows' `harness_rev` no longer matches the new part's, and
  the merge is **refused**. There is no way around that and it is correct: a cells-file change means
  the harness changed. The re-record is therefore a **full-golden re-record** on the new harness
  revision, run once, in a single commit, with the diff expected to touch only the three cells plus
  `meta.json`. The `harness_rev_note` field (already used, see the golden's current `meta.json`) is
  where the reason is written, in prose, naming the three cells and the digests of the three plugin
  tarballs used.
- **`host_triple`** — the checked-in golden was recorded on `aarch64-apple-darwin`. CI records its own
  golden fresh on `x86_64-unknown-linux-gnu` (`ci.yml:1405-1410`) and caches it. Both are legitimate;
  the differ refuses to compare across revisions unless told to (`replay.sh:15-17`).

**Then, and only then, the baseline.** `replay.sh --rebaseline` rewrites `owed-baseline.txt` from the
current golden's PASS rows. After the re-record it must contain **four** `plugins.store-persist|*`
ids, not one. That single line-count is the durable guarantee from §1.3: from that commit on, a
backend dropping out of coverage is red on every subsequent run.

**When it is re-recorded.** Only ever for a named reason, and each reason names its own step:
1. the harness changes (`cells.json`, `normalize.py`, `oracle-config.sh`, … — whatever
   `harness-rev.sh` hashes);
2. a **new published store plugin release** enters `plugin-digests.tsv` (§5.3);
3. a store backend **image** pin moves in a way that changes observable behaviour (rare; a version
   bump within `postgres:16` should not, and if it does, that is the finding).

Never on a schedule, never "to make it green".

### 3.2 (b) Candidate recording per stage

Unchanged in shape; only the cell count grows. `record.sh --bin target/release/busbar --plane all`
(`ci.yml:1411-1415`), then `replay.sh` (`:1416-1417`). With services present the three cells become
owed and the candidate must reproduce them byte-for-byte — including `usage_after_restart`,
`chat_after_restart` and `store_errors`, the three effects `store-persist.sh:14` names as the ones
that catch "a binary whose store calls are the wrong SHAPE: every request still answers 200 and
nothing else in this cell moves."

That is not a theoretical catch. It is the class of defect tracker row **B12** records — the ABI-2
adapter sending a row shape the published sqlite store rejected, so usage silently stopped
persisting. `store_errors` on **three more backends** is three more chances to catch the next one.

### 3.3 (c) The plugin functional probes, per backend

`probe-store.sh` is complete and unrun-in-this-repo. Wire it:

- **`plugin-functional.yml` gains a `services:` block**, conditional on `inputs.plugin_kind == 'store'`
  and on a new `service` input, using the same ternary-image idiom `plugin-ci.yml:154-165` already
  uses. It gains `STORE_SETTINGS` construction for the three server-backed aliases.
- **A new caller in busbar's own CI**: job `store-functional`, matrix over
  `{sqlite, postgres, mysql, valkey}`, `fail-fast: false`, calling `plugin-functional.yml` with
  `plugin_ref` = the published 1.5.5-era tag (digest-pinned like the oracle's) and `busbar_version` =
  `this-tree`. This is precisely the "consumer contract tests in the busbar repo" the CI-health doc
  demands (`CI-HEALTH-2026-09-04.md:48-51`): a busbar change that breaks a store fails **in busbar's
  own PR**, not in three other repos the next morning.
- The owed id per leg stays one — `store:<alias>` — and `verdict.sh` stays the only thing that
  decides. Zero rows is red; an owed id with no row is `DID NOT RUN`, red in its own column.

Full tier only, and on the nightly. On a fast-tier feature-branch push it is skipped and
`gate-tier` says so out loud (`ci.yml:90-104`).

### 3.4 (d) `store_conformance` against each real backend

Today: 3 of 9 checks, against RAM. Two independent lifts, in order:

**Lift 1 — run all nine against the in-tree backends.** `store-memory` runs three
(`crates/store-memory/tests/store_conformance.rs:23,28,33`); `store-example-plugin` runs none. Both
should run the five plane-record checks (`:444`–`:577`), and `store-example-plugin`'s `FileStore`
(`crates/store-example-plugin/src/lib.rs:506`) should additionally run
`assert_append_audit_duplicate_seq` (`:230`), which `MemoryStore` legitimately cannot
(`store_conformance.rs:10-11` — it takes the trait's defaulted no-op). Pure Rust, no services, runs
in `check`.

**Lift 2 — run them through a dlopened published plugin.** This is the one that reaches the real
backends, and it needs a seam that does not exist: the suite takes `&dyn Store`
(`store_conformance.rs:125` et al) and no adapter yields one from a loaded plugin. But
`crates/plugin-loader/src/store_adapter.rs` is exactly the ABI-2→trait shim the binary already uses.
A new integration test in `crates/plugin-loader` that (i) loads the pinned published tarball,
(ii) opens it with a DSN from `BUSBAR_TEST_{POSTGRES,MYSQL}_URL` / `VALKEY_URL`, (iii) runs all nine
`assert_*` with `ns = format!("conf{}", std::process::id())` and its own cleanup — as the module doc
prescribes (`store_conformance.rs:24-27`) — closes the gap the module was written for:
*four backends settling the same trait ruling four different ways.*

That is the only instrument here that compares the backends **to each other**. The oracle proves one
backend against one prior busbar; the probe proves one pair works. Neither can see two backends
disagreeing about `delete_key` on an unknown id. This can.

Gate rule, matching `ci.yml:327-331`: skip when the URL env is unset **locally**; when `CI` is set,
an unset URL is a hard fail.

### 3.5 (e) Restart, WAL and data-dir hazards, ABI-2 loading

- **Restart** is not an extra test; it *is* the test, in both instruments — `store-persist.sh:93-104`
  and `probe-store.sh:175-197`. Both kill, wait for the port to free, reboot against the same store,
  and compare counters. Neither may ever be relaxed to a graceful shutdown: the interesting failures
  are the ungraceful ones.
- **WAL / data-dir**: the journal is memory-buffered when there is no `data_dir` and shipped through
  the store adapter's `append_batch` (tracker row G1); the `hazard|no-data-dir|files` and `…|logs`
  cells (row G8) pin that a store-less node leaves the filesystem exactly as 1.5.5 does. Those cells
  are **backend-independent today** and should stay that way — they are about *absence*. What is
  owed and missing is the counterpart on the far side: a store-backed node's `store_errors` count,
  which the four store-persist cells now carry on four backends instead of one.
- **ABI-2 loading** is already proven for all four by `plugins.load|store-*`
  (`ledger.tsv:2170-2173`, script `plugin-list.sh`), which asserts the kind/alias/signature/STATUS
  line. What those cells do **not** prove is that the ABI-2 *data path* is right on a server backend —
  which is §3.2's `store_errors` and §3.4's Lift 2. The window itself (`[2,4]`,
  `plugin-loader/src/registry.rs:55`) is covered by unit tests
  (`registry_tests.rs::store_abi_below_or_above_the_range_is_refused_naming_v2_to_v4`).
- **Named limit, written down rather than papered over.** The four durable-governance boot cells
  (`boot.refusal|BOOT-172`, `|BOOT-174`, `|BOOT-175`, `boot.warning|BOOT-W13`) are produced by
  `scripts/durable-governance-precondition.sh`, whose corruption technique is **SQLite-page-specific**
  — it flips the leading byte of a table's root page, "a real SQLite page-level corruption no
  migration can repair". There is no faithful postgres/mysql/valkey analogue, and inventing one would
  prove a different statement. These four stay sqlite-only, **as a named gap in this document**, not
  as a silent absence. If they are ever wanted per-backend, the honest form is a *refusing store*
  fixture, not a corrupted one.

---

## 4. Cadence, triggers, cost

| cadence | trigger | what runs | services | est. wall-clock added |
|---|---|---|---|---|
| **per-PR (fast subset)** | `pull_request`, any push | oracle: `plugins.load\|store-*` (4) + `plugins.store-persist\|store-sqlite` + `plugins.store-persist\|store-postgres`. Candidate only — golden is cached on `(asset digest, harness rev)` (`ci.yml:1372-1388`). | postgres | **+~2 min** on `shadow-oracle` (postgres up ~20 s; one store-persist cell ≈ 40 s: fetch-cached, validate, boot, mint, spend, kill, reboot, read) |
| **dev merge (FULL)** | push to `dev`/`qa`/`main`, or any PR | all four store-persist cells; `store-functional` matrix (4 legs); `store_conformance` Lift 1 + Lift 2 | postgres, mysql, valkey | **+~6 min** on `shadow-oracle` (3 extra cells ≈ 2 min, mysql readiness up to 120 s, valkey ~10 s); `store-functional` runs in **parallel**, ~6 min wall for its slowest leg |
| **nightly** | `schedule` (a new `store-matrix.yml`) | the full §5 matrix: 4 backends × {published 1.5.5 busbar, HEAD} × {published plugin by digest, plugin repo `dev` HEAD}; plus `store_conformance` on every combination | all | **~35–45 min** wall, ~16 parallel legs; does not block |
| **qa** | `qa-gate.yml` → `release-check.sh` | `phase-1-<alias>-binary` for all four (today sqlite only), `phase-2-suite-store-*` for the three suite entries | all, via `docker run` | `release-check.sh` is budgeted "up to ~2 hours" (`:59`) and is segmented (`qa-gate.yml` `slow` matrix, `timeout-minutes: 180`); three new binary phases add **~5 min** to the `plugins` segment |
| **release-stage** | push to `qa` | `gate` job's full suite with mysql added; `store-functional` against the **staged** artifacts, blocking | all | **+~8 min**, mostly parallel |
| **manual re-record** | `workflow_dispatch` | `record.sh` against the pinned 1.5.5 binary + pinned plugins, all four backends; uploads the recording as an artifact for review before it is committed | all | **~25 min** for a full 885-cell golden |

Reference points for the estimates: the `shadow-oracle` job is bounded at `timeout-minutes: 60`
(`ci.yml:1363`) and today fits comfortably; `check` is bounded at 75 and runs "~13 minutes warm, ~40
cold" (`ci.yml:322-323`). The single largest fixed cost in the whole cycle is **mysql's first-boot
datadir initialisation**, measured at up to 120 s (`release-check.sh:1531-1533`) — which is why mysql
is deliberately **not** in the per-PR subset.

**Why postgres and not sqlite alone in the fast subset.** sqlite exercises a file; postgres exercises
the network client, the connection lifecycle and a shared schema — the three things a monorepo change
is actually likely to break. It is also the only store whose `release_gate` is `required`
(`plugins.yaml`), so it is the one whose breakage most directly stops a ship.

---

## 5. Matrix and drift control

### 5.1 The three axes

| axis | values | pinned where |
|---|---|---|
| **backend version** | postgres 16, mysql 8, valkey 8, sqlite (in-plugin) | `service-images.tsv` (§2.1), by digest |
| **plugin ABI** | the window `[2, 4]`. Published stores are ABI **2**; `store-example-plugin` packs at **4** | `plugin-loader/src/registry.rs:55`, `busbar-plugin/src/cold/mod.rs:153` |
| **busbar stage branch** | `dev`, `qa`, `main`; plus published 1.5.5 as the oracle's reference | `golden-digests.tsv`, `.github/release-targets.json` |

The ABI axis needs a specific note. `STORE_ABI_WITH_NEW_OPS = 5`
(`plugin-loader/src/store_adapter.rs:98`) is **above** the window's ceiling, so
`speaks_new_ops()` is `false` for every loadable store and **every published store takes the ABI-2
adapter path**. ABI 3 and ABI 4 are inside the window but have **no published artifact to test with**.
The honest matrix is therefore:

- **ABI 2** — the four published tarballs, against real servers. The real coverage.
- **ABI 4** — `crates/store-example-plugin`, in-tree, hermetic. Proves the window's ceiling loads.
- **ABI 3** — **a named gap.** No artifact exists. It is inside the window by design (the widening to
  `[2,4]` was an explicit owner decision, recorded in `qa/design-bindings.json`), and the honest way to
  cover it is to pack `store-example-plugin` at `--abi-version 3` in the nightly and assert it loads —
  which is a *load* proof, not a *persistence* proof, and should be labelled as such.

### 5.2 A new store plugin release enters the matrix

Two registries, and the order matters:

1. **`plugins.yaml`** — the single source of truth for *what plugins exist*. One entry:
   `repo`, `kind: store`, `alias`, `crate`, `version_line`, `service`, `release_gate`, `gate`.
   `scripts/plugin-registry-check.sh` then goes **red until every consumer covers it** — release-check
   phase, sibling checkout, published release. Coverage is enforced, not remembered. A new `service`
   value additionally hard-errors in `release-check.sh:1579-1583` until a container spec is written.
2. **`testing/shadow-oracle/plugin-digests.tsv`** — four rows (one per triple) with the release tag,
   asset name and sha256. `fetch-plugin.sh` refuses anything else.
3. **Then, and only then**, a new cell pair in `cells.json` (`plugins.load|store-<x>` and
   `plugins.store-persist|store-<x>`), the golden re-record (§3.1), and the `owed-baseline.txt`
   rewrite.

A **version bump of an existing** store is the same minus step 1: new digests, re-record, new
baseline. This is the trigger from §3.1's list, item 2.

### 5.3 Proving a schema migration in a store plugin

The gap first, because it is total: **there is no schema-migration machinery, documentation, or test
anywhere in this repo.** Core has no migration runner and no schema version; each store plugin owns
its DDL entirely; `docs/plugins.md` has zero hits for "migration" (the `docs/migration-1.*.md` files
are *config* migration, `--migrate-config`, not database schema). What exists is a single behavioural
sentence, `docs/configuration.md:672-684`: usage rows accumulate forever and busbar has no prune path
on any backend.

So this is designed here for the first time. A plugin whose new version changes its schema must prove
**upgrade**, not just fresh-install, and the shape follows the instruments already in place:

**The upgrade cell.** A new script-driver cell family, `store-upgrade|store-<b>`, driven by a new
`scripts/store-upgrade.sh`, structurally a two-plugin variant of `store-persist.sh`:

1. boot busbar with the **old** published plugin version (by digest) against a fresh namespace;
2. mint a key, spend, read `/usage` — record it;
3. kill; swap **only** the plugin tarball to the new version (same busbar binary, same namespace,
   same DSN);
4. boot again — the plugin's own open-time migration runs;
5. read the key and its usage back; drive one more request; count `store_errors` across both boots.

The contract recorded is the same triple `store-persist.sh` already records —
`usage_after_restart`, `chat_after_restart`, `store_errors` — plus `survived`. A migration that
drops the money is then a byte diff on a named cell, not a support ticket. This runs **nightly and at
release-stage**, not per-PR: it is a plugin-release event, not a busbar-commit event.

**A backward step that must also hold**: the old busbar binary against the *new* plugin schema. If a
fleet rolls plugins ahead of binaries, the old binary must either work or refuse cleanly. That is the
same script with the two versions transposed, and its verdict may legitimately be a *clean refusal* —
which is still a recorded, compared outcome.

---

## 6. Failure handling

### 6.1 Red vs SKIP-with-a-named-gap

The oracle's rule is already exact; this cycle adds no exception to it.

**SKIP with a named gap** — legitimate in exactly these cases, each already implemented:
- the cell's precondition genuinely cannot be produced on this host (`record.sh:185` for an
  unappliable mutation, `:422` for a script that reported `status: -1`);
- a plane proven elsewhere (`record.sh:401` — mcp/a2a go through their conformance rigs);
- **new**: a store backend with no service configured, on a developer laptop —
  `SKIP  UNSUPPORTED: no <backend> service configured` (§3.1). A `SKIP` is *never green*: it prints a
  `::warning::… DID NOT VERIFY` (`lib.sh:53-57`) and it is not in the owed set.

**RED** — everything else, and specifically:
- a cell in `owed-baseline.txt` that the current golden no longer owes, with no `accepted-gaps.json`
  entry naming an owner and a rationale (`replay.sh:19-25`);
- a golden-owed cell absent from the candidate — `DID NOT RUN`, its own column, never green by
  silence (`replay.sh:7-9`, `lib.sh:13-17`);
- **zero rows** (`verdict.sh`, `record.sh:576` `ZERO ROWS IS RED`);
- a service that did not come up **on a promotion branch or a PR** — hard-fail, per §1.4;
- `store_errors > 0` on any backend. It is a **count, not text** (`store-persist.sh:110`) precisely so
  the message wording stays the plugin's business while "more than zero" stays busbar's finding.

### 6.2 Flake policy: no retry may hide a red

**No `continue-on-error`, no retry wrapper, and no re-run-to-green on any store leg.** The reason is
structural rather than stylistic: the ledger inversion (`lib.sh:9-19`) exists so that a probe that
fails records `FAIL` and *the next probe still runs* — "the auth exchange failed" never hides "and the
store did not persist either". A retry re-runs both and reports one number, which discards exactly
the information the inversion was built to keep.

What is legitimate — and is not a retry — is **bounded readiness polling before the measurement
starts**: `pg_isready` / `mysqladmin ping` / `valkey-cli ping` with the 60 s / 120 s / 60 s caps, and
`wait_for_http` on `/healthz` (`lib.sh:85-92`). Those decide *whether the test can begin*, never
*whether it passed*. Exceeding a cap is a red naming the service and dumping `docker logs`, which is
what `release-check.sh:1508-1513` already does.

Two flake sources are known and are handled by construction, not by tolerance:
- **shared-database interference** — closed by per-run namespacing (§2.5), not by retrying;
- **metering write-behind** — the recorder already polls to a fixed point (two consecutive agreeing
  scrapes) rather than sleeping, `record.sh:245-254`. `store-persist.sh:90`'s bare `sleep 0.5` before
  reading `/usage` is the weaker form and should adopt `settle_then_snapshot`'s discipline as part of
  step S2; a fixed sleep across a network round-trip to postgres is a flake waiting for a slow runner.

If a store leg is genuinely non-deterministic, the response is a **named gap with an owner** in
`accepted-gaps.json` and a tracker row — visible, dated, owned — never a silent retry.

### 6.3 Who is paged, and what the tracker says

- **PR / dev merge red** — the author. The failure is one cell id and one ledger row; the report
  artifact (`shadow-oracle-report`, `ci.yml:1418-1429`) carries `diverging.txt` and `owed-gaps.txt`.
- **nightly red** — no human is paged at 3 a.m. for a non-blocking matrix. It opens or updates a
  single issue, the pattern the CI-health doc asks for (`:56-58`: "opens/updates an issue when any is
  red for > 24 h"). Consecutive-night reds escalate to a blocking tracker row.
- **qa / release-stage red** — the release owner; it stops the ship by construction
  (`REQUIRED_WORKFLOWS: "CI,qa-gate,Release stage"`, `release.yml:249`).
- **The tracker row wording**, for whichever row is open: name the **cell id**, the **backend**, the
  **plugin digest** and **which of the three instruments** went red — because "postgres is broken" is
  not an actionable sentence and "`plugins.store-persist|store-postgres` diverges on
  `usage_after_restart`; store-postgres v1.0.6 `8d3cf84e…`; oracle only, probe green" is.

---

## 7. Ownership, the tracker, and the implementation plan

### 7.1 Rows this closes

**Closed now:**
- **A8** — "oracle coverage: postgres / mysql / valkey store-persist cells (services)". Closed by
  steps S1–S4 below: the three cells recorded PASS on the golden, owed on the candidate, named in
  `owed-baseline.txt`.

**Strengthened, and the reason to keep this cycle standing:**
- **F4** — "PB-37 call_with_legacy_default and PB-93 1.6.0 store verbs on an ABI-2 store tested":
  today tested on one backend, after this on four.
- **B12** — the money regression the sqlite store-persist cell caught (the ABI-2 adapter sending a row
  shape the published store rejected). Three more backends is three more chances to catch its
  successor.
- **I3** — "required status checks on dev; qa and main protections per the CI health doc": the store
  legs named here become part of that required set.
- **I4** — "`verify-1.6.0-done.sh` fully green": its PARITY group runs the full oracle
  (`scripts/verify-1.6.0-done.sh:226-246`), so it inherits the four cells and needs services present
  when it is run for real.
- **I5** — "release-stage on qa, release on main (nothing rebuilt)": §1.2's staged bar.

**Recurring rows this cycle creates** (they never close; they are the cycle):
- *store matrix nightly is green* — one row, re-opened whenever the nightly is red two nights running.
- *`plugin-digests.tsv` is current* — re-opened by a published store release (§5.2).
- *`service-images.tsv` is current* — re-opened monthly by the refresh job (§2.1).

### 7.2 Scripts and workflows that change

| file | change |
|---|---|
| `testing/shadow-oracle/cells.json` | drop `needs_fixture` on 3 cells; add SecretRef settings args |
| `testing/shadow-oracle/scripts/store-persist.sh` | settings from env; DSN redaction before `step`; skip-with-named-gap when unset; fixed-point settle instead of `sleep 0.5` |
| `testing/shadow-oracle/golden/1.5.5/{ledger.tsv,cells/,meta.json}` | re-recorded (S4) |
| `testing/shadow-oracle/owed-baseline.txt` | 890 → 893 ids |
| `testing/fleet-fixtures/service-images.tsv` | **new** — the one pinned image list |
| `testing/fleet-fixtures/store-services.sh` | **new** — local up/down/url/ns |
| `testing/shadow-oracle/scripts/store-upgrade.sh` | **new** — the migration cell driver (§5.3) |
| `.github/workflows/ci.yml` | mysql on `check` + `coverage`; three services on `shadow-oracle`; new `store-functional` job in the umbrella |
| `.github/workflows/plugin-functional.yml` | `service` input + conditional `services:` + `STORE_SETTINGS` |
| `.github/workflows/release-stage.yml` | mysql on `gate`; staged-artifact store probes |
| `.github/workflows/store-matrix.yml` | **new** — the nightly |
| `.github/workflows/monthly-refresh.yml` | re-pin `service-images.tsv` |
| `scripts/release-check.sh` | read `service-images.tsv`; `run_store_backend_e2e` for all four, not sqlite alone |
| `crates/store-memory/tests/store_conformance.rs`, `crates/store-example-plugin` | run all nine checks |
| `crates/plugin-loader` (new integration test) | `store_conformance` through the dlopened published plugin |

### 7.3 Implementation plan — numbered, PR-sized, each with its gate

| # | step | gate it must pass |
|---|---|---|
| **S1** | `service-images.tsv` + `store-services.sh` (up/down/url/ns). Prove `store-persist.sh` green against local postgres, mysql and valkey using the **published 1.5.5 binary** and the **pinned published plugins**. | `record.sh --bin <1.5.5> --filter 'plugins\.store-persist' --out …` yields **4 PASS rows**, zero SKIP. Red-proof each by pointing at a stopped server and confirming a *named gap*, not a pass. |
| **S2** | `cells.json` (drop `needs_fixture`, add SecretRef settings) + `store-persist.sh` (env settings, **redaction**, named-gap path, fixed-point settle). No golden change yet. | Unit-shaped red-proof: record one cell with a deliberately-wrong DSN; assert the credential appears in **no** file under `cells/`. `record.sh` with the env unset yields SKIP, not FAIL. |
| **S3** | Wire the services in CI: mysql on `check`; postgres+mysql+valkey on `shadow-oracle`; the workflow-image lint against `service-images.tsv`. | `ci.yml` green on a branch; the lint red-proofed by mutating one digest. |
| **S4** | **The re-record.** Full golden on the new harness rev against pinned 1.5.5 + pinned plugins; `merge-recordings.py` provenance honoured; `meta.json.harness_rev_note` written; `replay.sh --rebaseline`. One commit. | Diff touches only the 3 cells + `meta.json` + `owed-baseline.txt`. `replay.sh` on HEAD: **0 unaccepted divergences**, 893 owed. **Closes A8.** |
| **S5** | `plugin-functional.yml` gains `service`; new `store-functional` matrix job in `ci.yml`, in the umbrella `RESULTS` as a `full`-tier row. | 4 legs green against published artifacts; each red-proofed by pointing at a wrong alias. `verdict.sh` red on zero rows. |
| **S6** | `store_conformance` Lift 1 (all nine in-tree) then Lift 2 (through the dlopened plugin over a real DSN). | 9/9 on all four backends; hard-fail (not skip) when `CI` is set and a URL is unset. |
| **S7** | `store-matrix.yml` nightly (§4) + the issue-opening step. | One full green run; red-proofed by pinning a known-bad plugin digest. |
| **S8** | `release-check.sh` reads `service-images.tsv`; `run_store_backend_e2e` for all four; `release-stage.yml` gains mysql + staged probes. | `qa-gate` green; `--check-coverage` still tiles the phase set. |
| **S9** | `store-upgrade.sh` + the `store-upgrade|store-<b>` cells (§5.3), nightly + release-stage only. | Cells PASS on both binaries; red-proofed against a plugin pair with a deliberately-broken migration. |

### 7.4 The step that can start tonight, unattended, on local docker

**S1**, in full, and nothing beyond it — it writes two new files, changes no existing behaviour, and
is exactly the thing that turns the rest of this plan from a proposal into a measurement.

What it does, unattended, on one laptop with docker:

1. write `testing/fleet-fixtures/service-images.tsv` from the digests already in the four workflows;
2. write `testing/fleet-fixtures/store-services.sh` (up/down/url/ns), modelled on
   `release-check.sh:1492-1590`, on the offset ports `15432`/`13306`/`16379`;
3. `store-services.sh up all` and prove readiness;
4. `fetch-golden.sh` and `fetch-plugin.sh store-postgres store-mysql store-valkey store-sqlite` —
   all digest-pinned, all cached under `~/.cache/busbar-oracle`;
5. run `store-persist.sh` **directly** (it is runnable standalone by design — that is the whole point
   of `lib.sh:22-29`) once per backend, with `BUSBAR_BIN` = the published 1.5.5 binary and settings
   pointing at the local servers;
6. record, per backend, whether it went green and — if not — the exact failing step number and its
   effects. That artifact **is** the finding: it tells the owner whether the published 1.5.5 stores
   persist through this script as-is, or whether the script needs a change beyond settings.

Why it is safe to run unattended: it is read-only with respect to the repo apart from two **new**
files; it touches no CI; it needs no credentials beyond `busbar/busbar` against throwaway containers;
it uses offset ports that avoid both a developer's own servers and the oracle's port band; and every
container is `--rm` under an EXIT trap. If it fails, the failure is a local log, not a red gate.

The first thing it can tell us by morning is the answer to the question no one has asked yet: **do the
three published server-backed stores actually pass `store-persist.sh` today, or has A8 been hiding a
second finding behind the missing fixture?**

---

## 8. Open decisions for the owner

Each with a recommendation, so a decision is a yes/no rather than an essay.

**D1 — Does mysql go in the per-PR fast subset?**
Its 120 s first-boot datadir initialisation is the single largest fixed cost in the cycle.
**Recommendation: no.** postgres in the fast subset, mysql from the FULL tier up. mysql's
`release_gate` is `optional` in `plugins.yaml`; postgres's is `required`.

**D2 — Is the CI DSN a secret?**
**Recommendation: no.** `busbar:busbar@localhost` against a container with an eight-minute life is not
a credential, and treating it as one costs fork PRs their coverage for nothing. Keep it a workflow
literal. The rules that *do* matter are §2.4(a) — never in a committed file — and §2.4(c) — never in a
recording. No production DSN is configured for any of these jobs, ever.

**D3 — One golden with all four backends, or a per-backend golden?**
**Recommendation: one.** `merge-recordings.py` enforces single-provenance across parts by design
(`:21,39-42`); splitting the golden per backend would need four provenance sets and four baselines and
would make "the golden" ambiguous. One golden, three new rows.

**D4 — Should the store-persist cells be `plane: core` and therefore in the fast tier?**
They are `plane: core` today (`cells.json:30191`) and `shadow-oracle` is a **fast**-tier row
(`ci.yml:1644`), so postgres in the fast subset means one server container on every push to every
branch. **Recommendation: accept it.** ~20 s and one container; the alternative — a store regression
first surfacing on a `dev` merge — is the expensive one.

**D5 — Is a fully-provisioned failure ever allowed to be a SKIP?**
**Recommendation: no, on any promotion branch or PR.** Hard red, per §1.4 and `ci.yml:327-331`. SKIP is
reserved for a laptop with no docker. This is the decision most likely to be quietly eroded later, so
it is worth stating once, deliberately: *a store that could not be tested has not been tested.*

**D6 — Who owns `mysql`'s missing settings schema?**
`store-mysql` is a published, registry-listed plugin with **no `settings:` documentation anywhere in
`docs/`** (`docs/configuration.md:653-657` lists sqlite, postgres, valkey only). S1 will discover the
key empirically from the released tarball's manifest `settings_schema`.
**Recommendation: a docs row in the same commit as S2**, so the cycle does not encode an
undocumented key. If the answer turns out to be that mysql's schema differs in shape from the other
two, that is itself a finding worth a tracker row.

**D7 — ABI 3 coverage.**
Inside the window `[2,4]`, no published artifact exists. **Recommendation: pack
`store-example-plugin` at `--abi-version 3` in the nightly and assert it loads** — labelled a *load*
proof, not a *persistence* proof. The alternative (leaving ABI 3 entirely unexercised) makes the
window's middle value a claim rather than a fact.

**D8 — When does the nightly become blocking?**
**Recommendation: never, as a whole** — a blocking nightly trains people to re-run rather than to read.
Instead: two consecutive red nights promotes the specific failing leg into a **blocking tracker row**
with an owner. The signal escalates; the gate does not thrash.

**D9 — Do the sqlite-only durable-governance boot cells get per-backend counterparts?**
The corruption technique is SQLite-page-specific and has no faithful analogue elsewhere (§3.5).
**Recommendation: no. Keep them sqlite-only and keep the limit named in this document.** If
per-backend coverage of those boot paths is wanted, the honest instrument is a purpose-built
*refusing* store fixture, not a corrupted real one — a separate piece of work, worth its own row.

**D10 — Does `release-check.sh` adopt the pinned digests?**
It uses floating tags today (`postgres:16`, `mysql:8`, `valkey/valkey:8`), so the **qa gate is not
pinned to the bytes CI is pinned to**. **Recommendation: yes, adopt them (S8).** The counter-argument —
that floating tags catch upstream breakage early — is real but is the nightly's job, where a break is
information rather than a blocked release.
