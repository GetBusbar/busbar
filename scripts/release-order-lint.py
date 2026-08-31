#!/usr/bin/env python3
"""release-order-lint - nothing may be tagged until it has been verified from the consumer side.

WHAT THIS GUARDS, AND WHY A LINT RATHER THAN A COMMENT.

busbar's release used to mint the version name FIRST: landing on main pushed `vX.Y.Z`, that tag
push fired both release.yml and docker.yml, and everything was built and published under a name
that already existed in public. Consumer verification, however thorough, therefore ran after the
fact and could only report damage. v1.5.3 shipped that way - the GitHub release published with
five of seven assets, `getbusbar/busbar:1.5.3` never built at all while the docs told users to pin
it, and putting it right meant deleting the release and the tag and re-cutting.

Docker Hub has TAG IMMUTABILITY enabled on getbusbar/busbar. A published tag CANNOT be
overwritten, so that is not merely untidy: a broken version is permanent, and the remedies are
deleting the tag (which has needed owner scope that was not available) or burning a version
number.

The order is now build -> stage under a throwaway name -> verify from the consumer side ->
promote. That order lives in the shape of the workflow graph, and a workflow graph is edited by
people in a hurry during an incident. Every rule below is a way the old order could come back by
accident, and each one has a specific, observed failure behind it. The self-test proves every rule
RED against a synthetic violation before the real check is trusted - a guard nobody has watched
fail is not a guard.

Usage:
    scripts/release-order-lint.py [--root .]
    scripts/release-order-lint.py --selftest
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile

WORKFLOWS = ".github/workflows"

# The jobs allowed to create a user-facing name. Everything here must be downstream of the staged
# consumer verification.
#
# THE QA/MAIN SPLIT (2026-08-27). The build half and the name-minting half no longer share a
# workflow: release-stage.yml (push to `qa`) builds, stages, verifies, and RECORDS the staged
# digest; release.yml (push to `main`) resolves that record fail-closed and promotes it. So the
# gate the promote must sit downstream of is `resolve-staged` (the record re-verification, in
# release.yml), while `verify-staged` (the staged consumer verification itself) lives in
# release-stage.yml and must gate the RECORD being written. R10 below is the split's own rule:
# main never rebuilds, qa never names.
PROMOTE_JOBS = ("promote-image", "promote-release")
VERIFY_GATE = "verify-staged"      # in release-stage.yml; gates record-staged
RESOLVE_GATE = "resolve-staged"    # in release.yml; gates the promote jobs


class Finding(list):
    """Accumulates human-readable violations. Empty means green."""


# ---------------------------------------------------------------------------------------------
# A DELIBERATELY SMALL PARSER, AND THE REASON IS DEPENDENCIES.
#
# This lint runs in `structure-lint`, the cheapest job in ci.yml, which installs nothing. PyYAML is
# present on today's ubuntu-latest image but that is a property of the runner image, not of
# anything this repository controls, and a gate that silently stops running when a base image
# changes is worse than no gate. Everything below needs only: the top-level block a line belongs
# to, the job a line belongs to, and each job's `needs:`. Indentation gives all three.
# ---------------------------------------------------------------------------------------------


def top_level_block(text: str, name: str) -> str:
    """Return the text of a top-level `name:` block (its header line plus all indented lines)."""
    out, grab = [], False
    for line in text.splitlines():
        if re.match(r"^%s:" % re.escape(name), line):
            grab = True
            out.append(line)
            continue
        if grab:
            if line.strip() == "" or line.startswith((" ", "\t")):
                out.append(line)
            else:
                break
    return "\n".join(out)


def jobs(text: str) -> dict:
    """Map job id -> that job's text, for every 2-space-indented key under `jobs:`."""
    block = top_level_block(text, "jobs")
    found, cur, buf = {}, None, []
    for line in block.splitlines()[1:]:
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            if cur:
                found[cur] = "\n".join(buf)
            cur, buf = m.group(1), [line]
        elif cur:
            buf.append(line)
    if cur:
        found[cur] = "\n".join(buf)
    return found


def needs_of(job_text: str) -> list:
    """The job ids a job depends on, from either `needs: a` or `needs: [a, b]`."""
    m = re.search(r"^    needs:\s*(.+?)\s*$", job_text, re.M)
    if not m:
        return []
    raw = m.group(1).strip()
    if raw.startswith("["):
        raw = raw.strip("[]")
    return [p.strip().strip("'\"") for p in raw.split(",") if p.strip()]


def depends_on(all_jobs: dict, start: str, target: str) -> bool:
    """Is `target` anywhere upstream of `start` in the needs graph?"""
    seen, stack = set(), list(needs_of(all_jobs.get(start, "")))
    while stack:
        j = stack.pop()
        if j == target:
            return True
        if j in seen:
            continue
        seen.add(j)
        stack.extend(needs_of(all_jobs.get(j, "")))
    return False


def strip_comments(text: str) -> str:
    """Blank out comment lines. Every rule below is about CODE; this file is heavily commented and
    a rule that matched its own prose would be unfixable without deleting the explanation."""
    return "\n".join("" if line.lstrip().startswith("#") else line for line in text.splitlines())


# ---------------------------------------------------------------------------------------------
# THE RULES
# ---------------------------------------------------------------------------------------------


def check(root: str) -> Finding:
    bad = Finding()
    wf = os.path.join(root, WORKFLOWS)

    def read(name: str):
        p = os.path.join(wf, name)
        return open(p, encoding="utf-8").read() if os.path.exists(p) else None

    release = read("release.yml")
    stage = read("release-stage.yml")
    docker = read("docker.yml")
    verify = read("verify-deploy.yml")

    # R1. NO WORKFLOW MAY BE TRIGGERED BY A VERSION TAG.
    # This is the root of the old order. If a `v*` tag push causes a build, then the tag has to
    # exist before the build, and the name is public before anything has verified it. Under the
    # new order a tag is an OUTPUT of a green release, so nothing may key off one.
    for name in sorted(os.listdir(wf)) if os.path.isdir(wf) else []:
        if not name.endswith((".yml", ".yaml")):
            continue
        text = strip_comments(read(name) or "")
        on = top_level_block(text, "on")
        if re.search(r"^\s*-\s*[\"']?v\*", on, re.M):
            bad.append(
                "R1 %s is triggered by a `v*` tag push. A tag must be the RESULT of a verified "
                "release, never its trigger: keying a build off a tag means the version name is "
                "public before one consumer check has run against it, which is how v1.5.3 shipped "
                "five of seven assets under a name that could not be taken back." % name
            )

    # R2. `tag-on-main.yml` MUST NOT COME BACK.
    # It read Cargo.toml on a main push and pushed the tag immediately. Its version read and its
    # idempotency guard now live in release.yml's `plan` job, which computes the same tag but does
    # not push it until the promote.
    if os.path.exists(os.path.join(wf, "tag-on-main.yml")):
        bad.append(
            "R2 .github/workflows/tag-on-main.yml exists again. That workflow pushed the version "
            "tag the moment a commit landed on main, before anything was built - the exact order "
            "this design removes. release.yml's `plan` job owns the version read now, and its "
            "`promote-release` job owns pushing the tag, after verification."
        )

    if release is None:
        bad.append("R0 .github/workflows/release.yml is missing.")
        return bad
    rel = strip_comments(release)
    rjobs = jobs(rel)

    if stage is None:
        bad.append(
            "R0 .github/workflows/release-stage.yml is missing. Without the qa staging workflow "
            "there is nothing that builds and verifies release bytes, and release.yml (promote-"
            "only by design) would have nothing honest to promote."
        )
        return bad
    stg = strip_comments(stage)
    sjobs = jobs(stg)

    # R3. THE RELEASE MUST BE CREATED AS A DRAFT.
    # A draft has real, downloadable assets but does not resolve as `releases/latest`, is not
    # listed, and materialises no git tag. That is what makes it safe to build against and safe to
    # abandon. `--verify-tag` is specifically called out because it is the flag the old flow used
    # and it CANNOT work here: there is no tag to verify.
    # SCOPED TO THE `draft` JOB, AND THE REASON IS A SELF-TEST THAT CAUGHT ITSELF LYING. An earlier
    # revision searched the whole file for `--draft` after `gh release create`. `promote-release`
    # runs `gh release edit --draft=false`, which contains the substring `--draft`, so deleting the
    # real `--draft` flag from the create call left the rule GREEN. The mutation test is what found
    # it. Match the flag as a whole token, inside the one job that may create a release.
    draft_job = sjobs.get("draft", "")
    if not re.search(r"(?<![=\w])--draft(?![=\w])", draft_job):
        bad.append(
            "R3 release-stage.yml creates a GitHub Release without `--draft`. A non-draft release "
            "is immediately listed and immediately resolves as releases/latest, so the version is "
            "public before verification - and publishing also materialises the git tag. On the qa "
            "branch that would publish EVERY iteration."
        )
    for label, body in (("release.yml", rel), ("release-stage.yml", stg)):
        if "--verify-tag" in body:
            bad.append(
                "R3 %s still passes `--verify-tag`. Under this design no tag exists when the "
                "release is created; the draft is anchored with `--target <sha>` instead." % label
            )

    # R4. EVERY PROMOTE MUST BE DOWNSTREAM OF THE STAGED CONSUMER VERIFICATION.
    # This is the rule the whole restructure exists to state. A promote that does not depend on
    # `verify-staged` publishes without a gate, and the graph is where that dependency lives -
    # there is no other place to assert it.
    for j in PROMOTE_JOBS:
        if j not in rjobs:
            bad.append("R4 release.yml has no `%s` job; the promote step is missing." % j)
        elif not depends_on(rjobs, j, RESOLVE_GATE):
            bad.append(
                "R4 release.yml's `%s` job does not depend, even transitively, on `%s`. Under the "
                "qa/main split the record re-verification IS the promote's gate: skipping it means "
                "minting a user-facing name over a digest nothing re-proved (absent, stale, or "
                "contradicted by the registry), which is the entire defect this design removes."
                % (j, RESOLVE_GATE)
            )
    # The other half of the same seam: the RECORD may only be written after the staged consumer
    # verification passed. A record written unconditionally would let release.yml promote bytes
    # whose verification failed, with every check in resolve-staged still green.
    if "record-staged" not in sjobs:
        bad.append(
            "R4 release-stage.yml has no `record-staged` job. Without the record there is no "
            "seam: release.yml's resolve-staged would refuse every promote (fail-closed, but "
            "permanently), or someone will 'fix' that by rebuilding on main."
        )
    elif not depends_on(sjobs, "record-staged", VERIFY_GATE):
        bad.append(
            "R4 release-stage.yml's `record-staged` job does not depend, even transitively, on "
            "`%s`. The record is the promote's only input, so writing it before the staged "
            "consumer verification passed publishes-by-proxy: main would happily retag a digest "
            "whose verification failed." % VERIFY_GATE
        )

    # R5. THE STAGED VERIFICATION MUST ACTUALLY BE IN STAGING MODE, AGAINST THE STAGED IMAGE.
    # Calling verify-deploy.yml without `stage: staging` would run the public sweep against an
    # unpublished version: it would fail on channels that are correctly still pointing at the
    # previous release, and the natural "fix" is to delete the gate. Omitting `image_ref` is worse
    # and quieter - the image checks would fall back to the PUBLISHED pin and go green on the
    # PREVIOUS release while claiming to have verified this one.
    vs = sjobs.get(VERIFY_GATE, "")
    if not vs:
        bad.append(
            "R5 release-stage.yml has no `%s` job. The staged consumer verification is what the "
            "recorded digest's credibility rests on; without it the record certifies an unverified "
            "build." % VERIFY_GATE
        )
    if vs:
        if "stage: staging" not in vs:
            bad.append(
                "R5 release-stage.yml's `%s` job does not pass `stage: staging` to verify-deploy.yml. "
                "The public sweep asserts downstream channels that only move after publication, "
                "so it cannot be the pre-promote gate." % VERIFY_GATE
            )
        if "image_ref:" not in vs:
            bad.append(
                "R5 release-stage.yml's `%s` job does not pass `image_ref`. Without it the image checks "
                "verify the PUBLISHED pin - the previous release - and pass while proving nothing "
                "about the artifact being cut." % VERIFY_GATE
            )

    # R6. THE FAN-OUT MUST NOT FIRE BEFORE THE RELEASE IS REAL.
    # `notify-downstream` tells every downstream repo to go and consume this release. Firing it off
    # the build jobs (which is where it used to hang) means telling nineteen repos to consume
    # something that may never be promoted.
    if "notify-downstream" in rjobs and not depends_on(rjobs, "notify-downstream", "promote-release"):
        bad.append(
            "R6 release.yml's `notify-downstream` job does not depend on `promote-release`. The "
            "fan-out would announce a release that is not published, so every downstream repo "
            "would chase a version that does not exist yet or may never exist."
        )

    # R7. DOCKER.YML MUST NOT EMIT A VERSION TAG FROM A BUILD.
    # `type=semver` gated on an input is the exact shape that let a bare dispatch publish only
    # `test` while a human believed a release had been rebuilt, and it is also the shape that
    # publishes `X.Y.Z` straight out of a build. `latest` as a raw tag in the build's `tags:` block
    # is the same defect for the moving pointer. Both names are created by the promote job now,
    # from bytes that have already been verified.
    if docker is None:
        bad.append("R0 .github/workflows/docker.yml is missing.")
    else:
        dtext = strip_comments(docker)
        djobs = jobs(dtext)
        build_side = "\n".join(t for j, t in djobs.items() if j != "promote")
        if "type=semver" in build_side:
            bad.append(
                "R7 docker.yml emits `type=semver` from a build job. A build must never decide, on "
                "its own, that a version exists: that tag is immutable on Docker Hub and cannot be "
                "taken back. Only the `promote` job may create `X.Y.Z`, from an already-verified "
                "digest."
            )
        if re.search(r"type=raw,value=latest", build_side):
            bad.append(
                "R7 docker.yml emits `latest` from a build job. `latest` is what "
                "`docker pull getbusbar/busbar` reads, so moving it from a build publishes an "
                "unverified image to every user who does not pin. Only the `promote` job may move "
                "it."
            )
        if "promote" not in djobs:
            bad.append(
                "R7 docker.yml has no `promote` job. The manifest-only retag is the primitive that "
                "lets `X.Y.Z` be the EXACT digest verification pulled and ran, rather than a second "
                "build that ought to match it."
            )

    # R9. NOTHING IS RELEASED FROM A RED COMMIT, AND THERE IS NO WAY AROUND IT.
    #
    # Owner, 2026-08-08: "nothing should ever be released red", "or ignored", and on the question of
    # a logged human override, "0 permission ever on anything". GetBusbar/headroom-hook published
    # v2.0.5 with red CI; the red was on a list headed "KNOWN, TRACKED, NOT BLOCKING", which is
    # ignoring with paperwork. So the gate must exist, everything must be downstream of it, and the
    # escape hatch must not exist - a waiver IS the permission-to-ignore mechanism.
    if "branch-green" not in rjobs:
        bad.append(
            "R9 release.yml has no `branch-green` job. Nothing may be cut from a red commit, and "
            "the gate cannot be a convention: it has to be a job every other job is downstream of."
        )
    else:
        for j in PROMOTE_JOBS + (RESOLVE_GATE,):
            if j in rjobs and not depends_on(rjobs, j, "branch-green"):
                bad.append(
                    "R9 release.yml's `%s` job is not downstream of `branch-green`, so it would run "
                    "on a red commit." % j
                )
    # The stage workflow carries its own branch-green (scoped to the required workflow names; see
    # the comment there for why the scope differs), and the expensive build must sit behind it for
    # the same reason the promote sits behind release.yml's: nothing is built from a known-red
    # commit.
    if "branch-green" not in sjobs:
        bad.append(
            "R9 release-stage.yml has no `branch-green` job. The staging build would run on a "
            "commit already known red, spending the full PGO pipeline on bytes that cannot ship."
        )
    else:
        for j in ("gate", "targets"):
            if j in sjobs and not depends_on(sjobs, j, "branch-green"):
                bad.append(
                    "R9 release-stage.yml's `%s` job is not downstream of `branch-green`, so it "
                    "would run on a red commit." % j
                )
    # THE ABSENCE OF AN ESCAPE HATCH IS ITSELF THE RULE. These are the names such a hatch arrives
    # under; naming them here means adding one is a build failure with a message that explains why,
    # rather than a plausible-looking input nobody questions.
    #
    # Scoped to the `on:` block (where an input would be DECLARED) and to `inputs.` references
    # (where one would be READ), not to the file's prose. The refusal messages in `branch-green`
    # say the words "no waiver" and "no bypass" out loud, on purpose, and a rule that forbade the
    # explanation of itself would be unfixable.
    for label, body in (("release.yml", rel), ("release-stage.yml", stg)):
      trigger_block = top_level_block(body, "on")
      for token in ("override_red_ci", "allow_red", "force_release", "skip_ci_check",
                    "ignore_red", "red_waiver", "release_waiver", "bypass_ci"):
        declared = re.search(r"^\s+%s:" % re.escape(token), trigger_block, re.M)
        read = re.search(r"inputs\.%s\b" % re.escape(token), body)
        if declared or read:
            bad.append(
                "R9 %s declares or reads a `%s` input. There is NO bypass of the "
                "red-branch gate: no override input, no force flag, no waiver, no exception list. "
                "That absence is the feature - a waiver IS the permission-to-ignore mechanism, and "
                "permission-to-ignore is what shipped a red release. If a check should not block a "
                "release, change or delete the CHECK." % (label, token)
            )
    # `continue-on-error` on the gate is the silent version of the same thing: the job goes red, the
    # release carries on, and nothing downstream can tell.
    for label, jb in (("release.yml", rjobs), ("release-stage.yml", sjobs)):
        if re.search(r"^\s+continue-on-error:\s*true", jb.get("branch-green", ""), re.M):
            bad.append(
                "R9 %s's `branch-green` job sets `continue-on-error: true`, which turns the "
                "red-branch gate into a decoration: it reports red and the run proceeds anyway."
                % label
            )

    # R10. MAIN NEVER REBUILDS, QA NEVER NAMES. This is the split's own invariant, and it is the
    # one an incident is most likely to erode: "just rebuild it on main real quick" reintroduces
    # the exact promoted-bytes-are-not-the-verified-bytes defect the owner named when asking for
    # the split ("we shouldn't be building again on main as that build is not technically what we
    # QA'd"), and a promote path in the stage workflow would mint names on every qa iteration.
    for marker, why in (
        ("build-artifact.yml", "calls the binary build workflow"),
        ("pgo-build", "runs the PGO build script"),
        ("docker/build-push-action", "builds and pushes an image"),
        ("cargo build", "compiles"),
    ):
        if marker in rel:
            bad.append(
                "R10 release.yml contains `%s` (%s). release.yml is PROMOTE-ONLY: every byte it "
                "names must have been built, verified and recorded by release-stage.yml on `qa`. "
                "A build here ships bytes that are 'technically not what we QA'd' - the exact "
                "defect the split removes. Build on qa; promote the record." % (marker, why)
            )
    for j, jt in rjobs.items():
        if "docker.yml" in jt and re.search(r"^\s+staging_tag:", jt, re.M):
            bad.append(
                "R10 release.yml's `%s` job passes `staging_tag:` to docker.yml, i.e. it asks for "
                "a fresh image BUILD on the main push. Main never rebuilds: the promote consumes "
                "the digest release-stage.yml recorded on qa." % j
            )
    for j, jt in sjobs.items():
        if "docker.yml" in jt and re.search(r"^\s+promote_to:", jt, re.M):
            bad.append(
                "R10 release-stage.yml's `%s` job passes `promote_to:` to docker.yml. The stage "
                "workflow must never mint `X.Y.Z`/`latest`: it runs on EVERY qa iteration, and "
                "only release.yml's promote (behind resolve-staged) may name bytes." % j
            )
    if "--draft=false" in stg:
        bad.append(
            "R10 release-stage.yml publishes the draft (`--draft=false`). Publishing is naming; "
            "it belongs to release.yml's promote-release, after the record is re-proved."
        )

    # R8. VERIFY-DEPLOY MUST STILL OFFER THE STAGING CONTRACT.
    # release.yml's gate is a call into this file. If the inputs go away the call breaks loudly,
    # but a rename that keeps the call syntactically valid while changing what it means would not,
    # so both halves of the contract are asserted here.
    if verify is None:
        bad.append("R0 .github/workflows/verify-deploy.yml is missing.")
    else:
        v = strip_comments(verify)
        for inp in ("stage:", "image_ref:"):
            if inp not in v:
                bad.append(
                    "R8 verify-deploy.yml no longer declares a `%s` input, so release.yml cannot "
                    "run it as the pre-promote gate." % inp.rstrip(":")
                )

    return bad


# ---------------------------------------------------------------------------------------------
# SELF-TEST: every rule proven RED before the real verdict is trusted.
# ---------------------------------------------------------------------------------------------

MUTATIONS = [
    (
        "R1 a v* tag trigger comes back on release.yml",
        "release.yml",
        lambda t: t.replace("  push:\n    branches: [main]", "  push:\n    tags:\n      - \"v*\""),
        "R1",
    ),
    (
        "R3 the release is created without --draft (stage workflow)",
        "release-stage.yml",
        lambda t: t.replace("--draft \\\n", ""),
        "R3",
    ),
    (
        "R4 promote-image stops depending on the staged-record verification",
        "release.yml",
        lambda t: t.replace("needs: [plan, resolve-staged]", "needs: [plan]"),
        "R4",
    ),
    (
        "R4 the staged record stops being gated on the staged verification",
        "release-stage.yml",
        lambda t: t.replace("needs: [plan, stage-image, verify-staged]",
                            "needs: [plan, stage-image]"),
        "R4",
    ),
    (
        "R5 the gate stops passing stage: staging (stage workflow)",
        "release-stage.yml",
        lambda t: t.replace("      stage: staging\n", ""),
        "R5",
    ),
    (
        "R5 the gate stops passing image_ref (stage workflow)",
        "release-stage.yml",
        lambda t: re.sub(r"^      image_ref: .*$", "", t, flags=re.M),
        "R5",
    ),
    (
        "R6 the fan-out is re-hung off the record resolution instead of the promote",
        "release.yml",
        lambda t: t.replace("needs: [plan, promote-release]\n    runs-on: ubuntu-latest",
                            "needs: [plan, resolve-staged]\n    runs-on: ubuntu-latest"),
        "R6",
    ),
    (
        "R7 a semver tag reappears in docker.yml's build",
        "docker.yml",
        lambda t: t.replace(
            "            type=raw,value=test,enable=",
            "            type=semver,pattern={{version}},value=v1.2.3\n            type=raw,value=test,enable=",
        ),
        "R7",
    ),
    (
        "R7 latest reappears in docker.yml's build",
        "docker.yml",
        lambda t: t.replace(
            "            type=raw,value=test,enable=",
            "            type=raw,value=latest\n            type=raw,value=test,enable=",
        ),
        "R7",
    ),
    (
        "R9 the red-branch gate is removed from the promote workflow",
        "release.yml",
        lambda t: t.replace("  branch-green:\n", "  branch-yellow:\n"),
        "R9",
    ),
    (
        "R9 the record resolution stops depending on the red-branch gate",
        "release.yml",
        lambda t: t.replace("    needs: [plan, branch-green]\n    runs-on: ubuntu-latest\n    outputs:",
                            "    needs: [plan]\n    runs-on: ubuntu-latest\n    outputs:"),
        "R9",
    ),
    (
        "R9 the staging build stops depending on the red-branch gate",
        "release-stage.yml",
        lambda t: t.replace("    needs: [plan, branch-green]\n    runs-on: ubuntu-latest\n    services:",
                            "    needs: [plan]\n    runs-on: ubuntu-latest\n    services:"),
        "R9",
    ),
    (
        "R9 an override input is added to bypass a red branch",
        "release.yml",
        lambda t: t.replace("  workflow_dispatch:\n",
                            "  workflow_dispatch:\n    inputs:\n      override_red_ci:\n        description: reason\n"),
        "R9",
    ),
    (
        "R10 a fresh image build sneaks back into the main promote",
        "release.yml",
        lambda t: t.replace("      promote_to: ${{ needs.plan.outputs.version }}",
                            "      staging_tag: staging-oops\n      promote_to: ${{ needs.plan.outputs.version }}"),
        "R10",
    ),
    (
        "R10 a promote sneaks into the qa staging workflow",
        "release-stage.yml",
        lambda t: t.replace("      staging_tag: ${{ needs.plan.outputs.staging_tag }}",
                            "      promote_to: 9.9.9\n      staging_tag: ${{ needs.plan.outputs.staging_tag }}"),
        "R10",
    ),
    (
        "R8 verify-deploy drops the staging inputs",
        "verify-deploy.yml",
        lambda t: t.replace("      image_ref:", "      unrelated_input:"),
        "R8",
    ),
]


def selftest(root: str) -> int:
    green = check(root)
    if green:
        print("SELFTEST FAILED: the repository is already RED, so a mutation proving nothing.")
        for b in green:
            print("  " + b)
        return 1
    print("baseline: GREEN (%s)" % root)

    failures = 0
    for label, filename, mutate, rule in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(os.path.join(root, WORKFLOWS), os.path.join(tmp, WORKFLOWS))
            path = os.path.join(tmp, WORKFLOWS, filename)
            original = open(path, encoding="utf-8").read()
            mutated = mutate(original)
            if mutated == original:
                print("  SELFTEST BROKEN: mutation '%s' changed nothing. The anchor it edits has "
                      "moved, so this rule is no longer being proven." % label)
                failures += 1
                continue
            open(path, "w", encoding="utf-8").write(mutated)
            got = check(tmp)
            if any(b.startswith(rule) for b in got):
                print("  RED as required: %s" % label)
            else:
                print("  SELFTEST FAILED: %s did NOT trip %s. Found: %s" % (label, rule, got or "nothing"))
                failures += 1

    # R2 has no in-file mutation: it asserts a FILE's absence, so the mutation is creating it.
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(root, WORKFLOWS), os.path.join(tmp, WORKFLOWS))
        open(os.path.join(tmp, WORKFLOWS, "tag-on-main.yml"), "w").write("name: tag-on-main\n")
        if any(b.startswith("R2") for b in check(tmp)):
            print("  RED as required: R2 tag-on-main.yml comes back")
        else:
            print("  SELFTEST FAILED: R2 did not trip when tag-on-main.yml was recreated.")
            failures += 1

    if failures:
        print("\nSELFTEST FAILED (%d rule(s) unproven). Do not trust this lint's verdict." % failures)
        return 1
    print("\nSELFTEST PASSED: every rule proven RED against a real violation.")
    return 0


# ---------------------------------------------------------------------------------------------
# --prove: WATCH THE DESIGN FAIL.
#
# "A failure leaves nothing public" is a claim about GitHub's job-scheduling semantics applied to
# this particular graph, and a design nobody has watched fail is not a design. This mode fails one
# job at a time and reports which jobs still run, so the claim is a thing you can read rather than
# a thing you are asked to believe.
#
# The semantics reproduced here are GitHub's own: a job runs when every job in its `needs:` has
# SUCCEEDED; a `needs:` on a failed or skipped job SKIPS the dependent, UNLESS the dependent carries
# `always()` or `!cancelled()`, in which case it runs anyway and must judge for itself. That last
# clause is not a detail: `!cancelled()` is exactly what let 1.5.3's `verify-assets` keep running
# after the build matrix went red, and it is exactly what must NOT appear on a promote job.
# ---------------------------------------------------------------------------------------------

# The jobs whose execution creates something a user can see. If any of these runs after a failure
# upstream of it, the design is broken.
PUBLIC_JOBS = {
    "promote-image": "mints getbusbar/busbar:X.Y.Z and moves latest (immutable, cannot be undone)",
    "promote-release": "pushes the git tag and publishes the release",
    "notify-downstream": "tells every downstream repo a release happened",
}


def simulate(all_jobs: dict, failed: str) -> dict:
    """Return job id -> 'success' | 'failure' | 'skipped', with `failed` forced to fail."""
    order, result = list(all_jobs), {}
    for _ in range(len(order) + 2):
        for j in order:
            if j in result:
                continue
            deps = needs_of(all_jobs[j])
            if any(d not in result for d in deps if d in all_jobs):
                continue
            cond = " ".join(re.findall(r"^    if:.*(?:\n      .*)*", all_jobs[j], re.M))
            forgiving = "always()" in cond or "!cancelled()" in cond
            upstream_bad = any(result.get(d) != "success" for d in deps if d in all_jobs)
            if upstream_bad and not forgiving:
                result[j] = "skipped"
            elif j == failed:
                result[j] = "failure"
            elif upstream_bad and forgiving:
                # It runs, but a guard job whose upstream is broken is expected to REPORT the
                # breakage, i.e. go red itself. That is what `verify-assets` is for.
                #
                # DELIBERATELY PESSIMISTIC. A job may carry `!cancelled()` AND a further
                # `needs.x.result == 'success'` clause that would really skip it (that is exactly
                # `consumer-verification`'s shape), and this does not model that second clause. It
                # therefore reports such a job as RUNNING when GitHub would skip it. Over-reporting
                # is the safe direction for a proof about what stays private: it can only ever
                # accuse the design of publishing too much, never excuse it.
                result[j] = "failure"
            else:
                result[j] = "success"
    return result


def prove(root: str) -> int:
    text = strip_comments(open(os.path.join(root, WORKFLOWS, "release.yml"), encoding="utf-8").read())
    all_jobs = jobs(text)
    failures = 0
    for failed in ["branch-green", "resolve-staged"]:
        if failed not in all_jobs:
            print("PROVE BROKEN: no job named %s" % failed)
            failures += 1
            continue
        res = simulate(all_jobs, failed)
        ran_public = [j for j in PUBLIC_JOBS if res.get(j) == "success"]
        print("\nIf `%s` FAILS:" % failed)
        for j in all_jobs:
            print("    %-24s %s" % (j, res.get(j, "?")))
        if ran_public:
            print("  BROKEN: these public-name jobs still ran: %s" % ", ".join(ran_public))
            failures += 1
        else:
            print("  NOTHING PUBLIC. Every name-minting job was skipped:")
            for j, what in sorted(PUBLIC_JOBS.items()):
                print("    %-20s %-8s (%s)" % (j, res.get(j), what))
    if failures:
        print("\nPROOF FAILED: a failure somewhere in this graph still publishes.")
        return 1
    print("\nPROOF: at every failure point, no git tag, no listed release, no container version "
          "tag, no fan-out. The next attempt is a clean retry.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--prove", action="store_true",
                    help="fail each job in turn and show that nothing public runs")
    args = ap.parse_args()
    if args.selftest:
        return selftest(args.root)
    if args.prove:
        return prove(args.root)
    bad = check(args.root)
    if bad:
        print("release-order-lint: FAIL\n")
        for b in bad:
            print("  " + b + "\n")
        print("The release order is: build -> stage under a throwaway name -> verify from the "
              "consumer side -> promote. A failure before the promote must leave NOTHING public.")
        return 1
    print("release-order-lint: OK - nothing can be tagged before it is verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
