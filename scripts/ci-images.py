#!/usr/bin/env python3
"""ci-images - the pinned CI service-container images, DERIVED from the workflows, never restated.

WHY THIS EXISTS AS A DERIVATION AND NOT AS A LIST.

`ci.yml` and `release.yml` each boot Postgres and Valkey as service containers, pinned by digest.
The GHCR mirror needs to know which images and which digests. The obvious thing is to write them
into the mirror workflow too, and that would be the third copy of the same fact.

busbar has already paid for that mistake once, one level up. v1.5.3 published five assets where seven
were expected because the release matrix and its verifier each carried their own platform list; the
fix was `.github/release-targets.json`, one file every consumer derives from. The comment in that
file says it plainly: a hardcoded expected list in the verifier "would have created a second place to
forget a platform, which is the same defect one level up".

A service container's `image:` MUST be a literal. GitHub does not expose the `env` context to
`jobs.<id>.services`, so the pin cannot be read from a file at that point even in principle. So the
workflows keep the literals and everything else DERIVES FROM THEM. That makes the workflows the
single source of truth rather than one copy among several.

AND IT ASSERTS THE TWO WORKFLOWS AGREE. `ci.yml`'s `check` job and `release.yml`'s `gate` job run
the identical test command against the identical services; if their pins ever diverge, the release
gate and the per-push gate are testing against different databases while reporting the same thing.
Nothing was checking that. Now a divergence is a build failure that names both digests.

Usage:
    scripts/ci-images.py --list       # JSON, one object per pinned image
    scripts/ci-images.py --selftest   # prove every rule RED before trusting the verdict
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile

WORKFLOWS = ".github/workflows"
# The workflows whose service containers are mirrored, and the job each pin must live in. Both are
# named so a pin appearing in only one of them is caught rather than silently accepted.
SOURCES = ("ci.yml", "release.yml")

# `image: <repo>:<tag>@sha256:<64 hex>` -- the digest half is REQUIRED by this pattern, so an
# unpinned `image: postgres:16` does not match and is reported as missing rather than parsed as
# fine. That direction matters: the failure mode to avoid is a parser that shrugs at an unpinned
# image and lets it through.
PINNED = re.compile(
    r"^\s*image:\s*(?P<repo>[a-z0-9._/-]+):(?P<tag>[A-Za-z0-9._-]+)@(?P<digest>sha256:[0-9a-f]{64})\s*$",
    re.M,
)
# Any `image:` at all, so an UNPINNED one can be named specifically.
ANY_IMAGE = re.compile(r"^\s*image:\s*(?P<ref>\S+)\s*$", re.M)

# The mirror's namespace. `ci-` prefixed so these are unmistakably build infrastructure and never
# confused with a busbar product image on the org's package list.
MIRROR_NS = "ghcr.io/getbusbar"


def _mirror_name(repo: str) -> str:
    """postgres -> ci-postgres; valkey/valkey -> ci-valkey. GHCR has no nested paths under an org."""
    return "ci-" + repo.rsplit("/", 1)[-1]


def _is_mirror(repo: str) -> bool:
    """Is this ref already one of OUR mirrors, rather than an upstream to be mirrored?"""
    return repo.startswith(MIRROR_NS.split("//")[-1] + "/ci-") or repo.startswith("ghcr.io/getbusbar/ci-")


def consumer_state(root: str) -> str:
    """Has ci.yml been repointed at the mirrors yet?

    DERIVED FROM THE TREE, NOT FROM A FLAG SOMEBODY SETS. This is what arms the anonymous-pull
    assertion in ci-images-mirror.yml, and a hand-maintained switch for that would be one more thing
    to forget in exactly the state where forgetting it is expensive. Reading the consumer's own
    `image:` lines means the guard arms itself AS A CONSEQUENCE of the consumer moving, which is the
    same "consumer moves last, on proof" ordering the release promote uses.

    Returns 'mirrored' once ci.yml pulls its service containers from GHCR, else 'upstream'.
    """
    path = os.path.join(root, WORKFLOWS, "ci.yml")
    if not os.path.exists(path):
        return "upstream"
    text = open(path, encoding="utf-8").read()
    for m in ANY_IMAGE.finditer(text):
        if _is_mirror(m.group("ref").split(":")[0].split("@")[0]):
            return "mirrored"
    return "upstream"


def collect(root: str):
    """Return (images, problems). `images` is one dict per distinct pinned image."""
    problems: list[str] = []
    per_file: dict[str, dict[str, str]] = {}

    for name in SOURCES:
        path = os.path.join(root, WORKFLOWS, name)
        if not os.path.exists(path):
            problems.append("%s is missing, so its service-container pins cannot be derived." % name)
            continue
        text = open(path, encoding="utf-8").read()
        pinned = {}
        for m in PINNED.finditer(text):
            key = "%s:%s" % (m.group("repo"), m.group("tag"))
            # ONE file may pin the same logical image in several jobs (ci.yml's check + coverage
            # both carry postgres/valkey service blocks). Those pins must agree with EACH OTHER,
            # not merely with the other workflow: reducing to a dict silently let the last
            # occurrence win, so one job could drift to different bytes than its sibling in the
            # same file and nothing here would say so — the exact defect class this script exists
            # to remove, one directory closer to home.
            if key in pinned and pinned[key] != m.group("digest"):
                problems.append(
                    "%s pins `%s` at DIFFERENT digests in different jobs (%s vs %s). Two jobs in "
                    "one workflow running the same service on different bytes is the same split "
                    "brain as two workflows disagreeing." % (name, key, pinned[key], m.group("digest"))
                )
            pinned[key] = m.group("digest")
        per_file[name] = pinned

        # An `image:` that is NOT digest-pinned is the defect this whole exercise removes, so it is
        # named rather than skipped. Container-build `image:` lines do not appear in these files;
        # every `image:` here is a service container.
        for m in ANY_IMAGE.finditer(text):
            ref = m.group("ref")
            if "@sha256:" not in ref and not ref.startswith("${{"):
                problems.append(
                    "%s has an UNPINNED service image `%s`. A moving tag means the same commit "
                    "gets different bytes on different days, so a store-roundtrip failure can be "
                    "caused by a database nobody in this repository changed." % (name, ref)
                )

    # -- AGREEMENT, EXPRESSED OVER LOGICAL IMAGES RATHER THAN LITERAL REFS ---------------------
    #
    # ci.yml's `check` and release.yml's `gate` run the identical test command, so they must run it
    # against identical bytes. Comparing the literal `image:` strings expresses that only while both
    # files name the same registry. After step 3 ci.yml says `ghcr.io/getbusbar/ci-postgres:16` and
    # release.yml still says `postgres:16`, and a literal comparison then finds no shared key and
    # QUIETLY STOPS CHECKING -- the gate that stopped gating.
    #
    # So each file is reduced to an EFFECTIVE DIGEST per LOGICAL image ("postgres:16"), reached
    # either directly or through its mirror, and the invariant is stated over that. It holds
    # identically before, during and after the transition.
    upstream_repos = {}          # mirror short-name -> upstream repo, learned from any upstream pin
    for pinned in per_file.values():
        for key in pinned:
            repo = key.rsplit(":", 1)[0]
            if not _is_mirror(repo):
                upstream_repos[_mirror_name(repo)] = repo

    def logical(key):
        """`postgres:16` -> ('postgres:16', False); `ghcr.io/.../ci-postgres:16` -> ('postgres:16', True)."""
        repo, _, tag = key.rpartition(":")
        if not _is_mirror(repo):
            return "%s:%s" % (repo, tag), False
        upstream = upstream_repos.get(repo.rsplit("/", 1)[-1])
        return (("%s:%s" % (upstream, tag)) if upstream else None), True

    effective = {}               # file -> {logical key -> (digest, via_mirror)}
    for fname, pinned in per_file.items():
        eff = {}
        for key, digest in pinned.items():
            lk, via = logical(key)
            if lk is None:
                problems.append(
                    "%s pins mirrored image `%s`, but no workflow pins the upstream it mirrors, so "
                    "nothing proves it carries the bytes the release gate runs against."
                    % (fname, key)
                )
                continue
            eff[lk] = (digest, via)
        effective[fname] = eff

    if len(per_file) == len(SOURCES):
        a, b = effective[SOURCES[0]], effective[SOURCES[1]]
        for lk in sorted(set(a) | set(b)):
            if lk not in a or lk not in b:
                missing = SOURCES[0] if lk not in a else SOURCES[1]
                problems.append(
                    "`%s` is pinned in one workflow but reached by neither pin nor mirror in %s. "
                    "ci.yml's `check` and release.yml's `gate` run the identical test command and "
                    "must run it against the identical services." % (lk, missing)
                )
            elif a[lk][0] != b[lk][0]:
                problems.append(
                    "`%s` resolves to DIFFERENT digests: %s has %s%s, %s has %s%s. The per-push "
                    "gate and the release gate would run against different bytes while reporting "
                    "the same thing."
                    % (lk, SOURCES[0], a[lk][0], " (via its mirror)" if a[lk][1] else "",
                       SOURCES[1], b[lk][0], " (via its mirror)" if b[lk][1] else "")
                )

    merged = {}
    for pinned in per_file.values():
        merged.update(pinned)
    upstreams = {k: v for k, v in merged.items() if not _is_mirror(k.rsplit(":", 1)[0])}

    # A PARSER THAT FINDS NOTHING MUST NOT READ AS "NOTHING TO DO". That is the vacuous pass, the
    # same shape as the counts Worker that logged every failure and returned normally, so a refresh
    # which updated nothing reported success. The floor is 2 because these workflows have always
    # booted both a Postgres and a Valkey.
    if len(upstreams) < 2:
        problems.append(
            "derived only %d pinned UPSTREAM service image(s) from %s. Refusing to report success "
            "on an empty or truncated list: a mirror job that copies nothing and exits 0 is exactly "
            "the failure this guard exists to prevent." % (len(upstreams), " and ".join(SOURCES))
        )

    images = []
    for ref in sorted(upstreams):
        repo, tag = ref.rsplit(":", 1)
        images.append(
            {
                "source": "%s@%s" % (repo, merged[ref]),
                "repo": repo,
                "tag": tag,
                "digest": merged[ref],
                "mirror": "%s/%s:%s" % (MIRROR_NS, _mirror_name(repo), tag),
                "mirror_repo": "getbusbar/%s" % _mirror_name(repo),
            }
        )
    return images, problems


# ---------------------------------------------------------------------------------------------
# SELF-TEST: every rule proven RED before the real verdict is trusted.
# ---------------------------------------------------------------------------------------------

MUTATIONS = [
    (
        "the two workflows disagree about a digest",
        "ci.yml",
        # EVERY occurrence, not the first: ci.yml legitimately pins the same image in more than one
        # job (check + coverage). `collect()` reduces a file to one digest per logical image, so a
        # mutation that corrupts only the first pin is overwritten by the intact twin and the
        # injected violation vanishes — the self-test then fails itself ("Got: nothing") despite
        # the rule being sound. Mutating every pin keeps the injection visible however many jobs
        # carry the pin.
        lambda t: t.replace(
            "image: postgres:16@sha256:95206741", "image: postgres:16@sha256:00000000"
        ),
        "DIFFERENT digests",
    ),
    (
        "a service image loses its digest pin",
        "ci.yml",
        lambda t: re.sub(
            r"image: (valkey/valkey:8)@sha256:[0-9a-f]{64}", r"image: \1", t, count=1
        ),
        "UNPINNED service image",
    ),
    (
        "an image is pinned in only one of the two workflows",
        "release.yml",
        lambda t: re.sub(
            r"^\s*image: valkey/valkey:8@sha256:[0-9a-f]{64}\s*$", "        image: scratch@sha256:"
            + "b" * 64, t, count=1, flags=re.M
        ),
        "reached by neither pin nor mirror",
    ),
]


def selftest(root: str) -> int:
    images, problems = collect(root)
    if problems:
        print("SELFTEST FAILED: the repository is already RED, so a mutation proves nothing.")
        for p in problems:
            print("  " + p)
        return 1
    print("baseline: GREEN -- %d pinned image(s):" % len(images))
    for i in images:
        print("    %-42s -> %s" % (i["source"][:42], i["mirror"]))

    failures = 0
    for label, filename, mutate, expect in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(os.path.join(root, WORKFLOWS), os.path.join(tmp, WORKFLOWS))
            path = os.path.join(tmp, WORKFLOWS, filename)
            original = open(path, encoding="utf-8").read()
            mutated = mutate(original)
            if mutated == original:
                print("  SELFTEST BROKEN: mutation '%s' changed nothing; its anchor has moved, so "
                      "this rule is no longer being proven." % label)
                failures += 1
                continue
            open(path, "w", encoding="utf-8").write(mutated)
            _, got = collect(tmp)
            if any(expect in g for g in got):
                print("  RED as required: %s" % label)
            else:
                print("  SELFTEST FAILED: %s did not report %r. Got: %s" % (label, expect, got or "nothing"))
                failures += 1

    # THE STEP-3 TRANSITION, PROVEN BOTH WAYS. Once ci.yml is repointed at the mirrors, the
    # "both workflows agree" invariant has to survive -- and the natural failure is that it silently
    # stops being checked because the two files no longer share a key. So the repointed shape is
    # proven GREEN when the digests match (the twin) and RED when they do not, and `consumer_state`
    # is proven to flip. Without the green twin, a rule that rejected EVERYTHING would look correct.
    def _repoint(text, digest=None):
        import re as _re
        def sub(m):
            d = digest or m.group(2)
            return "        image: ghcr.io/getbusbar/ci-postgres:16@%s" % d
        # EVERY pin, for the same reason the digest-disagreement mutation above replaces every
        # occurrence: a repoint that moves only the first postgres pin leaves the intact duplicate
        # to win `collect()`'s per-file reduction, and the red twin's injected disagreement is
        # never seen ("Got: nothing").
        return _re.sub(r"^(\s*)image: postgres:16@(sha256:[0-9a-f]{64})\s*$", sub, text,
                       flags=_re.M)

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(root, WORKFLOWS), os.path.join(tmp, WORKFLOWS))
        cip = os.path.join(tmp, WORKFLOWS, "ci.yml")
        before = open(cip, encoding="utf-8").read()
        after = _repoint(before)
        assert after != before, "the repoint mutation matched nothing; its anchor has moved"
        open(cip, "w", encoding="utf-8").write(after)
        state = consumer_state(tmp)
        _, got = collect(tmp)
        if state == "mirrored" and not got:
            print("  GREEN twin: ci.yml repointed at a mirror with the matching digest is accepted, "
                  "and consumer_state flips to 'mirrored'")
        else:
            print("  SELFTEST FAILED: the repointed-and-correct shape should be GREEN with "
                  "state='mirrored'. state=%s problems=%s" % (state, got or "none"))
            failures += 1

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(root, WORKFLOWS), os.path.join(tmp, WORKFLOWS))
        cip = os.path.join(tmp, WORKFLOWS, "ci.yml")
        wrong = "sha256:" + "c" * 64
        before = open(cip, encoding="utf-8").read()
        after = _repoint(before, wrong)
        assert after != before, "the repoint mutation matched nothing; its anchor has moved"
        open(cip, "w", encoding="utf-8").write(after)
        _, got = collect(tmp)
        if any("different bytes" in g for g in got):
            print("  RED as required: a mirrored image pinned to a different digest than its upstream")
        else:
            print("  SELFTEST FAILED: a mirrored image disagreeing with its upstream was accepted. "
                  "Got: %s" % (got or "nothing"))
            failures += 1

    # THE VACUOUS-PASS RULE, proven by removing the pins entirely rather than by argument.
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(os.path.join(root, WORKFLOWS), os.path.join(tmp, WORKFLOWS))
        for f in SOURCES:
            p = os.path.join(tmp, WORKFLOWS, f)
            t = open(p, encoding="utf-8").read()
            open(p, "w", encoding="utf-8").write(
                re.sub(r"^\s*image: .*@sha256:[0-9a-f]{64}\s*$", "", t, flags=re.M)
            )
        _, got = collect(tmp)
        if any("Refusing to report success on an empty" in g for g in got):
            print("  RED as required: no pinned images at all is a failure, not a no-op")
        else:
            print("  SELFTEST FAILED: an empty pin list did not fail. Got: %s" % (got or "nothing"))
            failures += 1

    if failures:
        print("\nSELFTEST FAILED (%d rule(s) unproven). Do not trust this script's output." % failures)
        return 1
    print("\nSELFTEST PASSED: every rule proven RED against a real violation.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--list", action="store_true", help="emit the pinned upstream images as JSON")
    ap.add_argument("--consumer-state", action="store_true",
                    help="print 'mirrored' if ci.yml pulls from GHCR, else 'upstream'")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest(args.root)
    if args.consumer_state:
        print(consumer_state(args.root))
        return 0
    images, problems = collect(args.root)
    if problems:
        for p in problems:
            print("::error::ci-images: " + p, file=sys.stderr)
            print("ci-images: " + p, file=sys.stderr)
        return 1
    if args.list:
        print(json.dumps(images))
    else:
        for i in images:
            print("%s -> %s" % (i["source"], i["mirror"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
