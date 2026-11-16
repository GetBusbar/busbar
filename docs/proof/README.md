# Build proof manifests

The Build Proof Dashboard manifest was once collated by `cargo xtask proof-manifest`. That collator,
and the GitHub workflows that ran it, are retired. No CI job in this tree produces or refreshes a
manifest today ([what CI checks](../ci.md)), and no manifest is committed under `docs/proof/`.

The seed manifests (`dev.json`, `index.json`) that used to live here were a 2026-09-04 snapshot that
cited gate tooling and crate paths that no longer exist; they were removed rather than left to be
read as current build proof.

For what CI proves about a given commit, read that commit's pipeline in GitLab.
