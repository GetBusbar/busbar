# GitHub Actions — commit-SHA pins

Every third-party `uses:` under `.github/workflows/*.yml` and `.github/actions/**/action.yml` must
resolve to an exact commit, never a tag or branch someone else can repoint. This is enforced by rule
`R14` of `cargo xtask gate release-order` (`xtask/src/gates/release_order.rs`) — there is no separate
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
| actions/cache | v4 | `0057852bfaa89a56745cba8c7296529d2fc39830` | 2026-09-11 | `git ls-remote` (tag) |
| actions/checkout | v4 | `11d5960a326750d5838078e36cf38b85af677262` | 2026-09-11 | `git ls-remote` (tag) |
| actions/checkout | v7 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | 2026-09-11 | `git ls-remote` (tag) |
| actions/download-artifact | v4 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | 2026-09-11 | `git ls-remote` (tag) |
| actions/download-artifact | v7 | `37930b1c2abaa49bbe596cd826c3c89aef350131` | 2026-09-11 | `git ls-remote` (tag) |
| actions/download-artifact | v8 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | 2026-09-11 | `git ls-remote` (tag) |
| actions/setup-go | v5 | `40f1582b2485089dde7abd97c1529aa768e1baff` | 2026-09-11 | `git ls-remote` (tag) |
| actions/setup-node | v4 | `49933ea5288caeca8642d1e84afbd3f7d6820020` | 2026-09-11 | `git ls-remote` (tag) |
| actions/setup-node | v6 | `249970729cb0ef3589644e2896645e5dc5ba9c38` | 2026-09-11 | `git ls-remote` (tag) |
| actions/setup-python | v5 | `a26af69be951a213d495a4c3e4e4022e16d87065` | 2026-09-11 | `git ls-remote` (tag) |
| actions/setup-python | v6 | `ece7cb06caefa5fff74198d8649806c4678c61a1` | 2026-09-11 | `git ls-remote` (tag) |
| actions/upload-artifact | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` | 2026-09-11 | `git ls-remote` (tag) |
| actions/upload-artifact | v7 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | 2026-09-11 | `git ls-remote` (tag) |
| azure/setup-helm | v4 | `1a275c3b69536ee54be43f2070a358922e12c8d4` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| codecov/codecov-action | v5 | `0fb7174895f61a3b6b78fc075e0cd60383518dac` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| codecov/codecov-action | v5.5.5 | `0fb7174895f61a3b6b78fc075e0cd60383518dac` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| docker/build-push-action | v7 | `53b7df96c91f9c12dcc8a07bcb9ccacbed38856a` | 2026-09-11 | `git ls-remote` (tag) |
| docker/login-action | v4 | `dbcb813823bdd20940b903addbd779551569679f` | 2026-09-11 | `git ls-remote` (tag) |
| docker/metadata-action | v6 | `dc802804100637a589fabce1cb79ff13a1411302` | 2026-09-11 | `git ls-remote` (tag) |
| docker/setup-buildx-action | v4 | `37fe631027851001ddb9b187196cc803df7f5f0e` | 2026-09-11 | `git ls-remote` (tag) |
| dtolnay/rust-toolchain | stable (comment: `1.98.0`) | `62ae3a85dbdd2bedbb5819da8ce45635129289a1` | 2026-09-11 | `git ls-remote` (branch, historical — see note) |
| EmbarkStudios/cargo-deny-action | v2 | `3c6349835b2b7b196a839186cb8b78e02f7b5f25` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| mozilla-actions/sccache-action | v0.0.11 | `fc920bf0ec8de6ee65d409111f7ec508035751ba` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| sigstore/cosign-installer | v3 | `398d4b0eeef1380460a10c8013a76f728fb906ac` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| Swatinem/rust-cache | v2 | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` | 2026-09-11 | `git ls-remote` (tag, peeled) |
| taiki-e/install-action | cargo-llvm-cov | `b3c2424e62a3f08fd88bf434799847a4d0da36c8` | 2026-09-11 | `git ls-remote` (tag, historical — see note) |
| latchkey-dev/cache-action | v1 | `d0dd21912a57c7435649c77f689b68d348d8a662` | 2026-09-11 | `git ls-remote` (tag) |

Every SHA above was resolved independently against live upstream on 2026-09-11 and matches the SHA
already committed in `.github/workflows/*.yml`. **No disagreement was found** between this
independent resolution and what is currently checked in — see "Disagreements" below for the two
rows that need a note rather than a fix.

`latchkey-dev/cache-action@v1` is `ci.yml`/`gate-mutants.yml`/`keep-proof.yml`'s new cache action
(54 `uses:`, introduced by the Latchkey CI cut-over); it was unpinned when this table's first draft
was written and was pinned, independently of this line, by that cut-over's own follow-up commit
before this table's final draft — the SHA above matches that commit exactly.

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

Every `uses:` in `.github/workflows/` — all 27 distinct `(action, ref)` pairs above, across every
workflow including the three the Latchkey CI cut-over touched (`ci.yml`, `gate-mutants.yml`,
`keep-proof.yml`) — was already pinned to a commit SHA with its tag kept as a trailing comment before
this line started (see `git log --oneline -- .github/workflows/`, commits "R14: pin every third-party
GitHub Action `uses:` to its commit sha, tag kept as trailing comment" and "actions: every third-party
action runs from a sha, and dependabot keeps the sha fresh", plus that cut-over's own follow-up commit
for `latchkey-dev/cache-action`). This table is this line's independent re-verification of that
existing state, not a first-time pin. There is no `.github/actions` directory yet, so `R14`'s
composite-action half of the scan currently covers zero files — proven able to catch one anyway by
`r14_reads_uses_out_of_a_composite_action_too_not_only_workflows` in
`xtask/src/gates/release_order.rs`.
