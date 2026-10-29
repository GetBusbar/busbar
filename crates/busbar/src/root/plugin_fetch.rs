// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins.fetch` DOWNLOAD, WIRED: the connector's download
//! (`busbar_core_connector::fetch`) over the process's one connector, under the root's own identity
//! ([`crate::root::connector::ROOT_OWNER`]; `NeedId(0)` there is the authorization server's, the
//! download rides `NeedId(1)` for a secured URL and `NeedId(2)` for a plaintext one).

use std::sync::Arc;

use busbar_contract::conn::{DeclaredConns, NeedId, PollConns};
use busbar_core_connector::fetch::{self, Table};

/// The process's one connector, under the root's own identity.
fn the_table() -> Table {
    let one = crate::root::connector::the();
    Table {
        owner: crate::root::connector::ROOT_OWNER,
        secured_need: NeedId(1),
        plain_need: NeedId(2),
        declared: Arc::clone(one) as Arc<dyn DeclaredConns>,
        conns: Arc::clone(one) as Arc<dyn PollConns>,
    }
}

/// The `plugins.fetch` download the root's fetch hands the loader: through the process's one
/// connector, under the operator's extra metadata denylist `blocked`, capped at
/// `config::DEFAULT_PLUGIN_FETCH_MAX_BYTES`.
///
/// A `plugins.fetch` GitHub pin resolves to the release asset `<repo>.tar.gz`. A busbar plugin
/// release publishes one signed tarball per target instead, `<repo>-<version>-<target>.tar.gz`
/// (`plugin-release.yml`), so when the first is not there the download asks for this binary's own
/// target's ([`release_asset`]) before it gives up.
pub fn downloader(blocked: &[String]) -> impl Fn(&str) -> Result<Vec<u8>, String> {
    let blocked: Vec<String> = blocked.to_vec();
    move |url: &str| {
        let get = |u: &str| {
            fetch::download(
                &the_table(),
                u,
                &blocked,
                busbar_kernel::config::DEFAULT_PLUGIN_FETCH_MAX_BYTES,
            )
        };
        get(url).or_else(|first| match per_target(url) {
            Some(other) => get(&other).map_err(|_| first),
            None => Err(first),
        })
    }
}

/// The release asset a GitHub release of a busbar plugin publishes for this binary's target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    /// Its download URL.
    pub url: String,
    /// Its file name.
    pub filename: String,
}

/// The asset `org/repo@tag` publishes for this binary's target (`BUSBAR_BUILD_TARGET`):
/// `https://github.com/org/repo/releases/download/<tag>/<repo>-<version>-<target>.tar.gz`, the
/// version being the tag without its leading `v`. `None` for a pin that is not `org/repo@tag`.
#[must_use]
pub fn release_asset(github: &str) -> Option<ReleaseAsset> {
    release_asset_for(github, env!("BUSBAR_BUILD_TARGET"))
}

/// [`release_asset`] for `target`.
#[must_use]
pub fn release_asset_for(github: &str, target: &str) -> Option<ReleaseAsset> {
    let (path, tag) = github.split_once('@')?;
    let (org, repo) = path.split_once('/')?;
    if org.is_empty() || repo.is_empty() || tag.is_empty() || repo.contains('/') {
        return None;
    }
    let version = tag.strip_prefix('v').unwrap_or(tag);
    let filename = format!("{repo}-{version}-{target}.tar.gz");
    Some(ReleaseAsset {
        url: format!("https://github.com/{org}/{repo}/releases/download/{tag}/{filename}"),
        filename,
    })
}

/// The per-target asset of a GitHub pin's URL (`.../<org>/<repo>/releases/download/<tag>/<repo>.tar.gz`),
/// or `None` for any other URL.
fn per_target(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://github.com/")?;
    let mut parts = rest.split('/');
    let (org, repo, releases, download, tag, file) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    if parts.next().is_some()
        || releases != "releases"
        || download != "download"
        || file != format!("{repo}.tar.gz")
    {
        return None;
    }
    release_asset(&format!("{org}/{repo}@{tag}")).map(|a| a.url)
}

#[cfg(test)]
#[path = "tests/plugin_fetch_assets.rs"]
mod asset_tests;
