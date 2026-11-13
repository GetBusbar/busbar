// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! busbar-publish-gate: verify, sign and publish one busbar release. It refuses anything it
//! cannot prove.
//!
//! The qa -> main move is judged in CI, and CI builds the CANDIDATE. CI holds no signing key and
//! publishes nothing. This tool is the rest, run by the owner from his own clone at the release
//! commit with his hardware keys present:
//!
//! - `verify`: every rule over the candidate and the owner's trust file. Offline apart from
//!   read-only GitHub and registry lookups. Writes `release-evidence.json`.
//! - `sign`: verify again, then show the full commit, the key-list diff and the digests. ONE
//!   release manifest lists every plugin tarball (name, version, target, canonical sha256); the
//!   release signer signs it ONCE (--k1-sign-cmd), and `busbar-plugin-pack seal` puts it, with the
//!   trust file's root-signed keys document, into each tarball and verifies the chain
//!   (docs/design/release-trust.md). K2 (the release key, FIDO2 ed25519-sk) signs SHA256SUMS,
//!   SHA256SUMS.plugins, IMAGES and release-evidence.json, and each signature is checked against
//!   the trusted allowed_signers.
//! - `upload`: pushes the images by digest (untagged), cosign-signs and verifies them, creates the
//!   GitHub Release as a draft on the owner's K2-signed version tag (G-15; the tag must already be
//!   on GitHub, the same tag object), uploads to Rekor, publishes, tags the images, and verifies
//!   everything again as a user would. Only then does it move X.Y, X and latest.
//! - `plugin-release <repo> <tag> --plugins DIR`: the same flow for one plugin released between
//!   core releases.
//! - `spot-rebuild`: rebuilds the host target locally and byte-compares it with the candidate.
//!   Report only.
//!
//! The owner's clone also holds the version tag v<V>: annotated, signed with K2 under the sshsig
//! namespace `git` (`git tag -s`, gpg.format=ssh) and naming the release commit (G-15).
//!
//! Exit: 0 verified, 1 refused, 2 usage, 3 a rule could not run.
//!
//! The candidate layout this reads (docs/verify.md, "For builders"):
//!
//! ```text
//! candidate.json   {"version","commit","repo","test_kit":{"tag","commit"},
//!                   "plugins":[{"repo","version","tag","commit"}]}
//! artifacts/       busbar-<target>.<archive> for every published target, busbar-openapi-v<V>.json,
//!                  plugin-index.json (the release index `busbar --migrate-config` reads)
//! plugins/         <repo>-<version>-<target>.tar.gz, UNSIGNED, for every plugin and plugin target
//! sboms/           busbar-v<V>-<target>.cdx.json for every published target and image platform
//! internal/        busbar-<musl target>.tar.gz (the binaries the image carries; not published)
//! oci/             busbar.oci.tar (an OCI layout of the multi-platform image)
//! SHA256SUMS       every file of artifacts/ and sboms/ (bare names)
//! conformance-manifest.json  the release's conformance manifest; conformance/ the receipts and
//!                  verdicts it was rendered from (G-C, docs/design/conformance-release.md)
//! IMAGES           `busbar sha256:<index digest>`
//! rebuild/         (optional) the second builder's artifacts/, byte-compared (report mode)
//! ```

pub mod archive;
pub mod cli;
pub mod conformance;
pub mod gate;
pub mod py;
pub mod security;
pub mod toml;
pub mod world;
