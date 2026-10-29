# The release publishes a real conformance manifest (G-C)

Status: design for 1.6.0. It implements WEBSITE-CLAIMS-1.6.0 section 3 (the release pipeline publishes a
real manifest) and cross-cutting item C1 (a tag is refused unless every public suite passes).

The publish gate itself (`scripts/release/publish_gate.py`, `candidate.py`; RELEASE.md "Publishing")
arrives with PR #1713. This design adds to it. Everything that does not need #1713's files lands on
`dev` on its own:

- `scripts/release/conformance_gate.py`: fetch, stamp validation, exceptions and the G-C rule;
- `scripts/conformance/sync.py --release`: the render;
- the `repo` field in the registry.

The hooks into #1713's files sit on a branch stacked on #1713:

- `candidate.py conformance-manifest`;
- G-C in `publish_gate.py verify`;
- `conformance_manifest_sha256` in the evidence;
- the upload step.

## 1. Where it runs

`candidate` is ModernCI's qa -> main check. It holds no key. It gains one slice:

```
candidate.py conformance-manifest --out DIR
  = python3 scripts/release/conformance_gate.py manifest --release <V> --commit <T> --out DIR
```

`T` is the release commit, i.e. the candidate's HEAD and the tag's target. `V` is
`crates/busbar/Cargo.toml`'s version. The shipped plugin pins are read at `T`:

- `dist/default/Cargo.lock`: the plugins compiled into the binary;
- `release/plugin-pins.tsv`: the tarball plugins (#1713).

A repo named in both files must name the same commit in both, or G-C refuses. `assemble` copies two
things into the candidate:

- `DIR/conformance-manifest.json`;
- `DIR/conformance/`, the fetched verdicts and their receipts.

The slice needs a ModernCI client with read access (`artifact`) in the candidate job. Wiring it into
`.ci/qa.yaml` is a branch-file change on `modernci-config`, which the lead owns.

## 2. Verdicts come from ModernCI only

Each suite is owned by the repo that runs it in its `testing/conformance/suites.tsv`. The registry
names that repo in a new required field:

```toml
[[suite]]
id = "mcp"
repo = "GetBusbar/busbar-plane-mcp"
```

`sync.py` refuses a registry entry without `repo`, so the map is never guessed. For every registered
suite, the expected commit is:

- **core suite** (`repo = GetBusbar/busbar`): `T`;
- **plugin suite**: `P`, the plugin's shipped pin from section 1. A suite whose repo ships no pin
  judges nothing that ships, so it is recorded as `not-run` with a reason.

`conformance_gate.py fetch` calls ModernCI once per repo:

```
modernci call artifact {"repo": R, "check": "conformance", "head": <T or P>, ...}
```

It writes `DIR/conformance/<owner>/<name>/`:

- `receipt.json`: what ModernCI answered, i.e. `repo`, `from`, `head`, `state` and the `sha`
  of the archive;
- `verdicts/<id>.json`: the `target/conformance/verdicts/*.json` members of the archive.

A repo that ModernCI has no output for at that head gets a receipt with `"missing": "<why>"` and no
verdicts. Nothing else is read:

- **A hand-placed file is ignored.** `conformance/verdicts/` in the tree is ignored at release. So
  is any file in the fetch directory that is not under a receipt.

### Plugin verdicts against another core pin

A plugin verdict must have `core_pin == T`. A stored verdict at another core pin must be re-run with
the plugin's `.busbar-ref` overridden to `T`. ModernCI's `measure` has no such override today
(`modernci call measure --help`: repo, from, check, again, change). So the fetcher's re-run hook
raises, and the suite is recorded as `not-run` with the reason "judged against core X, not T; no
re-run is possible". G-C then refuses it.

When ModernCI ships a core override, the hook calls it. The re-run's verdict is then used only if its
stamp names `T`.

Ruling (conformance lead, per KICKOFF "plugins test against a released core test kit"; it answers
the owner question above it): plugins pin `.busbar-ref` to the released test-kit commit `K` (G-12),
not to `T`. When the release names `K` (`--testkit K` on `manifest` and `gate`), a plugin verdict
counts when `core_pin == K`, and a stored verdict on any other core is re-run against `K` or refused.
Core's own suites still need `core_pin == T`. Without `--testkit`, the `core_pin == T` rule above
holds for plugins too.

## 3. Stamp validation

The judge in `testing/conformance/run.sh` (busbar-release `template/conformance/run.sh`) stamps each
verdict. A verdict counts only if all of the following hold. Otherwise its suite is `not-run`, with
the failing check as the reason.

- `schema == "busbar.conformance.verdict/1"`, `suite` equals the file stem, the fields are within the
  verdict schema, and the status and armed rules hold. These are `read_verdicts`'s rules today.
- `repo` equals the registry's `repo` for the suite, and equals the receipt's `repo`.
- `commit` equals the receipt's `head`. The receipt's `head` equals the expected commit: `T` for core,
  `P` for a plugin.
- `core_pin == T` for core's suites; for a plugin's, `core_pin == K` when the release names the
  test-kit commit `K`, else `T`.
- `run_id == "modernci:<repo>@<commit>:conformance"`.
- `evidence` is a ModernCI move URL for that repo with `head=<commit>`.
- Each verdict file sits under a receipt with no `missing`.

The manifest carries:

- at manifest level, `commit = T` and `release = V`;
- on each suite, `repo`, `commit`, `core_pin`, `evidence` and `verified_at` (the verdict's
  `generated_at`).

The bytes are canonical: sorted keys, two-space indent, LF, one trailing newline. `generated_at` is
the latest accepted verdict's time, so the same inputs always give the same bytes. `claim_for` keeps
the tier ceilings.

## 4. G-C, the publish-gate rule

`publish_gate.py verify` runs G-C over the candidate. It refuses, one `REFUSED G-C ...` line each, when
any of these holds:

1. The candidate's `conformance-manifest.json` is not byte-equal to a fresh render of the candidate's
   `conformance/` against the registry at `T`. This catches a hand-edited manifest.
2. The manifest's `commit` is not `T`, or its `release` is not `V`.
3. A `public = "true"` suite is not `pass` for `T`/`P`: a wrong repo, a wrong commit, or `core_pin`
   not `T`. A covering signed exception is the only way past this rule.
4. A plugin pin in `dist/default/Cargo.lock` differs from the commit whose verdict was used, or from
   `release/plugin-pins.tsv`.
5. **Pin freshness** (WEBSITE-CLAIMS 2a #4): a shipped pin of a suite-owning plugin is not that repo's
   `dev` head at tag time, unless a signed pin exception names that repo and commit.

### Signed owner exceptions

`release/conformance-exceptions.json` is committed at `T`, so it is judged and reviewed like any
change. Its K2 signature `release/conformance-exceptions.json.sig` sits beside it:

```json
{
  "schema": "busbar.conformance.exceptions/1",
  "release": "1.6.0",
  "suites": [{"suite": "fapi2", "status": "not-run", "reason": "OIDF submission pending"}],
  "pins":   [{"repo": "busbar-plane-mcp", "commit": "<40 hex>", "reason": "..."}]
}
```

- **The signature.** It is `ssh-keygen -Y sign -n busbar-release` with K2, verified against the trust
  file's `k2_allowed_signers` (identity `busbar-release`). This is the file namespace G-14 already
  restricts K2 to. An unsigned file, a bad signature or an unknown schema is refused (exit 1). A
  missing file means no exceptions.
- **Which suite it covers.** An exception covers a suite only for the release it names, and only
  while the suite's actual status equals the exception's `status`. The owner signs what he saw.
- **Never a pass.** `status` must be `fail` or `not-run`; an exception that says `pass` is refused.
  The manifest records the real status. An excepted suite's `reason` reads
  `owner exception (signed): <reason>; <verdict reason>`, and its `claim` stays null.

## 5. Sign (K2 now)

`release-evidence.json` is K2-signed in the ceremony. It gains:

- `conformance_manifest_sha256`: the sha256 of the candidate's `conformance-manifest.json`;
- `conformance`: `{"rule": "G-C", "public_pass": n, "excepted": [...]}`.

K3, the ModernCI DSSE over the manifest, comes with RP-7. It is not in this change.

## 6. Upload

`publish_gate.py upload` attaches `conformance-manifest.json` to the draft GitHub Release `v<V>`
before it is undrafted.

- **Before the upload**, it refuses unless the file's sha256 equals
  `release-evidence.json.conformance_manifest_sha256`.
- **After publishing**, it downloads the asset back and checks the same digest.

The rendered manifest is also what the release branch commits as `conformance/manifest.json`, so the
tree and the asset agree. `sync.py --release ... --write` writes it there.

## Tests (red first)

`scripts/release/test_conformance_gate.py` (no `busbar-plugin-pack` needed):

- `a_registered_public_suite_without_a_pass_refuses_the_tag`
- `a_verdict_stamped_for_another_commit_is_not_used`
- `a_hand_placed_verdict_is_ignored`
- `a_plugin_verdict_judged_against_another_core_pin_is_rerun_or_refused`
- `a_plugin_verdict_on_the_released_test_kit_counts`
- `a_stale_plugin_pin_is_refused`
- exceptions:
  - a signed exception lets a not-run suite through, and records it as not-run;
  - an exception claiming `pass` is refused;
  - a tampered exception is refused.

`scripts/conformance/test_sync.py`: the `--release` render. On the stacked branch,
`scripts/release/test_publish_gate.py` adds:

- G-C wired into `verify`;
- `conformance_manifest_sha256` in the evidence.

Neither Python suite runs in a ModernCI check today. Run them with `python3 -I <file>`.
