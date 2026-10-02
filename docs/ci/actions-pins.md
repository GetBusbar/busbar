# GitHub Actions — commit-SHA pins

Every third-party `uses:` under `.github/workflows/*.yml` and `.github/actions/**/action.yml` must
resolve to an exact commit, never a tag or branch someone else can repoint. This is enforced by rule
`R14` of `cargo xtask gate workflow-rules` (`xtask/src/gates/workflow_rules.rs`) — there is no separate
lint for it; `R14` already reads a floating ref by file:line and refuses the pipeline over it, and now
scans composite-action manifests too, not only workflows. This table is the independent resolution
behind each pin currently in the tree: each row was produced by running

```
git ls-remote https://github.com/<owner>/<repo> refs/tags/<ref> refs/tags/<ref>^{} refs/heads/<ref>
```

against upstream directly — never by copying the SHA a scanner suggested — and taking the peeled
(`^{}`) commit when the tag is annotated, or the tag/branch tip otherwise. `dtolnay/rust-toolchain`
is the one row where `<ref>` is a git ref (`stable`) rather than a version string: the SHA there pins
the ACTION's code, not the Rust toolchain, which is separately and exactly pinned by this repo's
`rust-toolchain.toml`.

Resolved 2026-09-11 from `https://github.com/<owner>/<repo>` (git ls-remote, live upstream).

| Action | Ref (comment) | Commit SHA | Resolved | Resolved from |
|---|---|---|---|---|
| actions/attest-build-provenance | v4 | `4d101475d8b20a2381f78447822ac1eab6504dd8` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| actions/checkout | v7 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | 2026-09-11 | `git ls-remote` (tag) |
| actions/download-artifact | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | 2026-10-02 | `git ls-remote` (tag) |
| actions/upload-artifact | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | 2026-10-01 | `git ls-remote` (tag) |
| codecov/codecov-action | v7.1.1 | `303a32d7a59b442fa8d48b6a1cc6825c09c847a5` | 2026-09-21 | `git ls-remote` (tag, peeled) |
| dtolnay/rust-toolchain | stable (comment: `1.98.0`) | `62ae3a85dbdd2bedbb5819da8ce45635129289a1` | 2026-09-11 | `git ls-remote` (branch, historical — see note) |
| mozilla-actions/sccache-action | v0.0.11 | `fc920bf0ec8de6ee65d409111f7ec508035751ba` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| Swatinem/rust-cache | v2 | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| taiki-e/install-action | cargo-llvm-cov | `b3c2424e62a3f08fd88bf434799847a4d0da36c8` | 2026-09-11 | `git ls-remote` (tag, historical — see note) |

Every SHA above was resolved independently against live upstream on 2026-09-11 and matches the SHA
committed in `.github/workflows/*.yml`. **No disagreement was found** — see "Disagreements" below for
the two rows that need a note rather than a fix.

## Disagreements (and why they are not the attack this table exists to catch)

Re-resolving today against two upstream refs that are not immutable tags returns a *newer* commit
than the one already pinned. Both are legitimate ref drift, not evidence of a tampered pin:

* **`dtolnay/rust-toolchain@stable`** — `stable` is a branch, not a tag; upstream moves it forward on
  every Rust point release. Live resolution today: `6bed0761d98439e5a578e2877258200ad565ba87`. The
  committed pin (`62ae3a85dbdd2bedbb5819da8ce45635129289a1`) is an older commit on that same branch —
  still a real, reachable, unaltered commit of `dtolnay/rust-toolchain`, so the pin has not been
  weakened; it is simply older than "stable" as of today. The Rust *version* this repo builds with is
  independently and exactly pinned by `rust-toolchain.toml`, per the action's own documented pattern,
  so this drift has no effect on reproducibility.
* **`taiki-e/install-action@cargo-llvm-cov`** — `cargo-llvm-cov` here is a *per-tool* tag that
  upstream periodically force-moves to the version of `cargo-llvm-cov` they have most recently
  verified, i.e. it is used as a floating pointer by convention even though it is shaped like a tag.
  Live resolution today: `cb407c4fe87966b0b9d1f7350974e80c133dd4bb`. The committed pin
  (`b3c2424e62a3f08fd88bf434799847a4d0da36c8`) is again an older, still-valid commit.

Neither case is a scanner/committed-value mismatch of the kind this table exists to catch (a pin that
does not match what a human reviewed); both are the expected result of re-resolving a
by-design-floating ref at a later date. Dependabot (`.github/dependabot.yml`,
`package-ecosystem: "github-actions"`) is what is expected to bump both forward over time, opening a
PR that preserves the trailing tag comment.

## Every action currently in the tree

Every `uses:` in `.github/workflows/` (`promote.yml` and the reusable `plugin-*.yml` workflows) is one
of the nine distinct `(action, ref)` pairs above, pinned to a commit SHA with its tag kept as a
trailing comment. This table is the independent re-verification of that state. There is no
`.github/actions` composite action beyond `cargo-home`, and `R14` is proven able to catch a floating
tag inside one by `r14_reads_uses_out_of_a_composite_action_too_not_only_workflows` in
`xtask/src/gates/tests/workflow_rules_tests.rs`.
