# History rewrite: closing the empty-bodied commit bodies

## What gets rewritten

Three landed commits on `integration/oracle-phase0` carry a subject line but no rationale in the
body (one carries nothing at all after the subject, two carry only a bare
`(cherry picked from commit <sha>)` trailer):

| sha (landed) | subject |
|---|---|
| `2bc50d2cb` | trust unit: restore the WHATWG first step's leading/trailing trim, at parity with the substrate |
| `d747f5831` | mutation rate limiter: sweep only windows strictly older than the current one, and clamp a regressing clock |
| `fcfcafb16` | kernel: the one runner of PlaneRecord legs — schema, op and size validated before the sink |

All three are security fixes. Only the message **body** of these three commits is rewritten — the
subject line, the tree (the actual file contents), the author, the committer, and every timestamp
are unchanged. `scripts/history-rewrite-empty-bodies.sh` proves the tree of every rewritten commit
is byte-identical to the original before it will touch a real ref, and refuses outright unless the
working tree is clean, the ref's tip matches an explicit `--expect-tip`, and every named sha is
verified — at run time, against the real repository, not trusted from a list — to be on the ref
with a body that is empty today.

A wider ledger sweep at one point named three additional empty-bodied commits believed to be on
this ref. Investigation for this rewrite found those three shas exist in the object database but
are **not reachable from any ref** (`git fsck --unreachable` reports them as dangling commits, and
`git merge-base --is-ancestor` fails against `integration/oracle-phase0`), consistent with the
audit note that those three are non-security and were already handled by a separate re-pick sweep.
They are excluded from this rewrite's scope for exactly that reason: the tool refuses to touch any
sha that is not currently an ancestor of the ref being rewritten, and there is nothing on this ref
for those three shas to name.

Note also: because a commit's identity (its sha) is computed over its parent's sha, every commit
**downstream** of a rewritten commit gets a new sha even though its own tree and message are
untouched — this is mechanical and unavoidable in any content-preserving history rewrite. It is not
the same thing as "touching" a commit's content; the dry run's tree-identity proof covers every
commit in the affected range, rewritten or not.

## Why

Three of the fixes closed here are security-relevant (an SSRF/credential-leak bypass in a
trust-boundary URL guard, a rate-limiter bypass reachable by a regressing wall clock, and a
validation gap in the kernel's record-leg runner). An advisory process depends on being able to
point at the commit that fixed each finding and read, from the commit itself, what the finding was
and why the fix closes it. A commit whose body says nothing does that job for nobody: a reader (an
auditor, a future maintainer, an external security researcher who receives a coordinated-disclosure
advisory) is left re-deriving the rationale from the diff alone, and a diff alone does not say
*why* a change matters or what it made newly safe. That gap is a hole in the audit trail, not a
cosmetic one, and it is closed once, deliberately, rather than left to accumulate.

This is treated as a rare, reviewed operation and not a casual amend:

- it targets a **closed, named set** of already-identified commits, never an open-ended range;
- the bodies are **drafted for human review** (`docs/security/rewrite-bodies.txt`) before anyone
  runs the tool for real;
- the tool's checks are enforced by the tool itself at run time against the live repository, not
  taken on faith from whoever invokes it.

## When

Scheduled as the **last boundary before the qa push** for this landing cycle. Every line has
finished landing and no slot is still live at that point, so the rewrite happens exactly once, no
in-flight slot has to rebase across it, and the runner that continues landing afterward restarts
cleanly against the one rewritten tip rather than needing to track two tips through a transition
window.

## Steps for the integrator, at that boundary

1. Confirm every landing slot for the cycle is finished (no slot live, nothing queued behind the
   rewrite's tip).
2. Review `docs/security/rewrite-bodies.txt` — the drafted body text for each of the three shas
   above — and edit it in place if the wording needs to change. Each block is
   `<sha><TAB><first body line>` followed by any further lines, terminated by a line that is
   exactly `%%%`.
3. Record the ref's current tip: `git rev-parse integration/oracle-phase0`.
4. Dry run first, always:
   ```
   scripts/history-rewrite-empty-bodies.sh \
     --ref integration/oracle-phase0 \
     --bodies docs/security/rewrite-bodies.txt \
     --expect-tip <tip-from-step-3>
   ```
   Confirm the printed old→new mapping and the tree-identity line for every entry, and confirm the
   only shas whose bodies changed are the three named above (every other commit in the range shows
   an unchanged body, only a remapped parent).
5. Run for real, from a clean working tree, once the dry run looks right:
   ```
   scripts/history-rewrite-empty-bodies.sh \
     --ref integration/oracle-phase0 \
     --bodies docs/security/rewrite-bodies.txt \
     --expect-tip <tip-from-step-3> \
     --for-real
   ```
6. **Re-pin every tip-keyed ledger the landing engine maintains for this branch.** Because the
   rewrite changes the sha of every commit from `2bc50d2cb` forward (mechanically, per the parent-
   chaining note above), anything that recorded a decision, a measurement, or a pick against one of
   those old shas — the land-done ledger, the gate re-pin ledger, `held.txt` cross-references, any
   `repin=<sha>` row — is now pointing at a sha that no longer exists on the ref. Re-run whatever
   the landing engine uses to re-key those ledgers against the new tip before resuming any landing
   work on this branch.
7. **Re-run the provenance trailer check.** Anything that verifies a commit's `(cherry picked
   from commit ...)` trailer still names a real, resolvable source commit needs to re-run against
   the new tip: this rewrite preserves each rewritten commit's own trailer verbatim (appended after
   the new body), but every *downstream* commit's sha changed, so any check that was keyed off the
   old downstream shas needs to re-anchor.
8. Update any queued verification line for the affected commits to run against the new shas.

## What this does not do

- It does not touch any commit's tree, subject, author, committer, or timestamps.
- It does not touch any commit outside the three named shas and their descendants.
- It does not run itself: the tool's default is a dry run, and `--for-real` is a separate,
  explicit flag with its own preconditions.
- It does not decide severity, exposure, disclosure, or backport scope for the underlying
  findings — those are owner/`SECURITY.md` decisions, tracked separately from this rewrite.
