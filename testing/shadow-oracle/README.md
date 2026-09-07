# The shadow oracle

Record one busbar binary through every cell, record another, diff them cell by cell. The golden is
the **published 1.5.5 release artifact**, fetched by pinned sha256 and never built from the tag; the
candidate is this tree's build. Same config, same mock, same keys-by-role, same normalizer — so a
difference is busbar's behaviour and nothing else.

The pieces:

| file | what it is |
| --- | --- |
| `cells.json` | every cell: its id, driver, request, and what makes it a pass |
| `record.sh` | the recorder — drives one binary through the cells, writes `cells/`, `raw/`, `ledger.tsv`, `meta.json` |
| `normalize.py` | turns a capture into a comparable cell (drops the clock, the ports, the host's own capabilities) |
| `diff-cells.py` | the differ — classes a divergence and weights it |
| `replay.sh` | golden vs candidate, with the owed-cell floor |
| `merge-recordings.py` | merges recordings made in disjoint parts into one |
| `harness-rev.sh` | the revision of everything that decides *what* is recorded and *how* it is compared |
| `golden/1.5.5/` | the committed, reviewed 1.5.5 recording — **the reference, never re-derived in CI** |

`replay-selftest.sh` and `fixture-gate-selftest.sh` prove the differ can see a diff and that the
fixture gate decides both ways, before anything expensive runs.

---

## The store cells, and the loop that fills them

### The problem

Three cells — `plugins.store-persist|store-postgres`, `…|store-mysql`, `…|store-valkey` — boot a
real durable backend, spend, restart and read back. Persistence *is* the thing under comparison, so
they cannot be recorded without Postgres, MySQL and Valkey actually running.

The committed golden was recorded on a laptop. Two of those three had no backend there, so their
ledger rows read:

```
plugins.store-persist|store-mysql	SKIP	UNSUPPORTED: …	named gap: the fixture this cell needs is not in the tree yet
```

`ci.yml`'s `shadow-oracle` job now boots the three services, so the **candidate** side records them.
That on its own proves nothing: a candidate recording with a gap on the golden side has nothing to
be diffed against. **A gap on both sides is not agreement**, and a gap on one side is not a verdict.

So the golden owes three cells that only a machine with the three backends can record.

### Why it takes two halves

The golden is the reviewed answer to *"what did 1.5.5 do"*. A gate that can rewrite its own
reference is not a gate — which is why `ci.yml` copies the committed golden in rather than
re-recording it, and why the same rule applies to whatever produces golden bytes.

So the loop is deliberately split:

- **a machine records** — `.github/workflows/oracle-record-store-cells.yml`. It runs under
  `contents: read`, records exactly the three ids, refuses anything that is not `PASS`, proves it
  left `golden/` untouched, and **uploads an artifact**. It cannot push and it never writes the
  golden.
- **a human accepts** — `import-store-cells.sh`. It merges the artifact into `golden/1.5.5`,
  re-stamps the provenance, and **prints the diff without committing**. Accepting bytes into the
  reference is a review, and it lands under a person's name.

### Running it

**1. Record.** Dispatch the workflow (it also runs weekly on its own):

```
gh workflow run oracle-record-store-cells.yml --ref <branch>
gh run watch <run-id>
```

It pins its three service containers to the same rows of `testing/fleet-fixtures/service-images.tsv`
that `ci.yml`'s shadow-oracle job pins — *the same bytes on both sides is what makes the comparison
mean anything* — and `scripts/service-images-check.sh` proves that as its first step, before
anything expensive.

**2. Read the notes.** The artifact carries `merge-notes.md`: the harness revision, the binary's
sha256, the host triple, the pinned images and the version string each backend answered with, and
the three verdicts. `raw/` is deliberately **not** in the artifact — it is the pre-normalisation
forensic tree and holds live minted `bbk_…` key material. `cells/` is the post-normalisation view
and is safe by construction; the golden checks in no `raw/` either, so the import needs none of it.

**3. Import.**

```
gh run download <run-id> -n oracle-store-cells-<run-id> -D /tmp/store-cells
testing/shadow-oracle/import-store-cells.sh /tmp/store-cells
```

It refuses a row that is not `PASS` (a gap imported over the golden would write the blind spot back
while the notes claimed three recordings) and refuses a foreign `binary_sha256` (same version string
is not the same bytes). It *does* accept harness and host skew — the artifact comes off a linux
runner and the rest of the golden off darwin — but records both, with a note naming which cells came
from where. `--selftest` drives both refusals over a fixture golden.

Then read the diff and commit it yourself.

**4. The candidate side needs no change.** `ci.yml`'s shadow-oracle job already boots the three
backends and records the tip's three cells; once the golden carries them, `replay.sh` compares them
like any other cell. Until then the golden's gap is named, not silent — `owed-baseline.txt` is what
stops an id quietly ceasing to be owed.

### If you change one side, change the other

The three fixture variables in `ci.yml`'s `Record the candidate` step and in
`oracle-record-store-cells.yml`'s job `env:` name the same backends on the same ports. A URL, a port
or an image changed on one side only is the failure that is hardest to read: the golden names a gap
where the candidate recorded, and the differ reports a divergence that is really a difference in how
the two were run. The image pins are held together by `scripts/service-images-check.sh`; the URLs are
held together by this paragraph and by the comment on each step.
