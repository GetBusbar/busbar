# What this directory relies on, and under which licence

Checked 2026-08-09. Recorded rather than assumed, because one of the two upstreams states its
licence twice and states it differently each time, and the other does not state one at all.

## `a2aproject/a2a-tck` — used, at a pinned commit, NOT vendored

Pinned commit: `5996b79f9cefa6fc390980e383e358a66fb9e49e` (2026-06-29).

**Its terms are ambiguous in its own tree.**

| Where | What it says |
|---|---|
| `LICENSE` | Apache License, Version 2.0 |
| `pyproject.toml` `[project] license` | `MIT` |

Both are permissive and both permit the use made here, so the ambiguity does not block anything —
but it does decide HOW it is used.

**What we do about it.** Nothing from `a2a-tck` is copied into this repository. `run-tck.sh` fetches
it at the pinned commit at run time, installs it into a throwaway virtualenv, and invokes it as a
tool. The only artefacts kept here are `baselines/*.json`, which are **our own measurements of a
third-party control** — a record of what we observed, not a copy of the suite. Nothing in them is
upstream text.

That is the deliberate posture: **do not vendor code whose terms disagree with themselves.** Running
a tool is not distribution; copying its source into a public repository is, and it is the act that
would force us to pick one of the two licences on the reader's behalf.

If the ambiguity is ever resolved upstream, the choice to fetch-rather-than-vendor can be revisited.
Until then this file is the answer to "what did you rely on, and under what terms".

## `a2aproject/a2a-itk` — NOT used

The Integration Testing Kit has **no LICENSE file at all** (verified against the repository contents
listing, 2026-08-09; the GitHub API reports `license: null`). No stated terms means no permission,
so it is not fetched, not vendored, and not relied on anywhere in this tree. It is named here only
so that "we did not use it" is a recorded decision rather than an omission somebody has to re-derive.

## `a2aproject/a2a-go` — used as a control binary, at a pinned version

`v2.4.0`, Apache-2.0 (unambiguous). Installed by `go install` at run time by both this directory and
`../a2a-harness/scripts/install-control.sh`; not vendored. The two must stay on the same version, or
the two instruments are describing different peers.

## `a2aproject/a2a-python` — used as a second control, at a pinned version

`a2a-sdk` `1.1.2` from PyPI, Apache-2.0 (unambiguous). Installed at run time by
`../a2a-harness/scripts/install-control.sh`; not vendored.
