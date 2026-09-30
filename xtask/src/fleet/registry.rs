//! `plugins.yaml` as the fleet reads it: the `fleet:` policy block and every `plugins:` entry with
//! its render fields resolved to their documented defaults. Read with `yaml_lite::parse_structure`
//! (the workflow subset of YAML, which this file stays inside); a field of the wrong type is an
//! error naming the entry, never a silent default.

use serde_json::Value;

use crate::ctx::Ctx;

pub const REGISTRY: &str = "plugins.yaml";

#[derive(Debug, Clone)]
pub struct Plugin {
    pub repo: String,
    pub kind: String,
    pub alias: String,
    pub crate_name: String,
    pub released: bool,
    pub manifest_name: String,
    pub asset_prefix: String,
    pub description: String,
    pub ci_service: String,
    pub busbar_checkout: bool,
    pub macos_test: String,
    pub extra_test: String,
    pub lib_only: bool,
    pub needs_prompt: String,
    pub needs_user: String,
    pub declares: String,
    pub bundle_image: String,
    pub bundle_env: String,
    pub keep: Vec<String>,
    /// Lines the rendered `.gitignore` carries after the fleet's own.
    pub gitignore: Vec<String>,
    /// Lines the rendered `NOTICE` carries after the fleet's own (a third-party credit).
    pub notice: Vec<String>,
    /// Position in the registry (the consumer-verify cron is staggered by it).
    pub index: usize,
}

#[derive(Debug, Clone)]
pub struct Fleet {
    pub pin_sha: String,
    pub pin_version: String,
    pub name_pattern: String,
    pub branches: Vec<String>,
    pub plugins: Vec<Plugin>,
}

impl Plugin {
    /// `<kind>-<name>`: the repo name without `busbar-`, and the logic crate's directory (the cdylib's
    /// is `<stem>-plugin`). Every plugin repo is exactly these two crate dirs.
    pub fn stem(&self) -> &str {
        self.repo.strip_prefix("busbar-").unwrap_or(&self.repo)
    }

    /// The two crate directories of a twin repo.
    pub fn crate_dirs(&self) -> [String; 2] {
        [self.stem().to_string(), format!("{}-plugin", self.stem())]
    }
}

impl Fleet {
    pub fn plugin(&self, repo: &str) -> Result<&Plugin, String> {
        self.plugins
            .iter()
            .find(|p| p.repo == repo)
            .ok_or_else(|| format!("`{repo}` is not a plugin repo in {REGISTRY}"))
    }

    /// The `.busbar-ref` line every repo must carry.
    pub fn busbar_ref(&self) -> String {
        format!("{} {}\n", self.pin_sha, self.pin_version)
    }
}

pub fn load(cx: &Ctx) -> Result<Fleet, String> {
    parse(&cx.read(REGISTRY)?)
}

fn s<'a>(v: &'a Value, key: &str, who: &str) -> Result<Option<&'a str>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(x)) => Ok(Some(x)),
        Some(other) => Err(format!("{who}: `{key}` must be a string, found {other}")),
    }
}

fn req<'a>(v: &'a Value, key: &str, who: &str) -> Result<&'a str, String> {
    s(v, key, who)?
        .filter(|x| !x.trim().is_empty())
        .ok_or_else(|| format!("{who}: `{key}` is required"))
}

fn b(v: &Value, key: &str, who: &str, default: bool) -> Result<bool, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(x)) => Ok(*x),
        Some(other) => Err(format!(
            "{who}: `{key}` must be true or false, found {other}"
        )),
    }
}

fn list(v: &Value, key: &str, who: &str) -> Result<Vec<String>, String> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| match i {
                Value::String(x) => Ok(x.clone()),
                other => Err(format!("{who}: `{key}` holds a non-string {other}")),
            })
            .collect(),
        Some(other) => Err(format!("{who}: `{key}` must be a list, found {other}")),
    }
}

pub fn parse(text: &str) -> Result<Fleet, String> {
    let doc = crate::yaml_lite::parse_structure(text).map_err(|e| format!("{REGISTRY}: {e}"))?;
    let fleet = doc
        .get("fleet")
        .ok_or_else(|| format!("{REGISTRY}: no `fleet:` block (the pin policy)"))?;
    let who = format!("{REGISTRY} fleet");
    let pin = req(fleet, "busbar_ref", &who)?;
    let mut it = pin.split_whitespace();
    let (sha, version) = match (it.next(), it.next(), it.next()) {
        (Some(sha), Some(v), None) => (sha.to_string(), v.to_string()),
        _ => {
            return Err(format!(
                "{who}: `busbar_ref` must be \"<40-hex sha> <version>\", found {pin:?}"
            ))
        }
    };
    if sha.len() != 40
        || !sha
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(format!(
            "{who}: `busbar_ref` sha {sha:?} is not a full 40-hex commit"
        ));
    }
    let name_pattern = req(fleet, "name_pattern", &who)?.to_string();
    crate::ere::Ere::new(&name_pattern).map_err(|e| format!("{who}: `name_pattern`: {e}"))?;
    let branches = list(fleet, "branches", &who)?;
    if branches.is_empty() {
        return Err(format!("{who}: `branches` is empty"));
    }
    let entries = match doc.get("plugins") {
        Some(Value::Array(a)) if !a.is_empty() => a,
        _ => return Err(format!("{REGISTRY}: `plugins:` is missing or empty")),
    };
    let mut plugins = Vec::new();
    for (index, e) in entries.iter().enumerate() {
        let repo = req(e, "repo", &format!("{REGISTRY} entry #{index}"))?.to_string();
        let who = format!("{REGISTRY} entry {repo}");
        let crate_name = req(e, "crate", &who)?.to_string();
        let service = req(e, "service", &who)?.to_string();
        let released = match e.get("released") {
            None | Some(Value::Null) => true,
            Some(Value::Bool(x)) => *x,
            Some(Value::String(x)) => !x.trim().eq_ignore_ascii_case("false"),
            Some(other) => {
                return Err(format!(
                    "{who}: `released` must be true or false, found {other}"
                ))
            }
        };
        plugins.push(Plugin {
            kind: req(e, "kind", &who)?.to_string(),
            alias: req(e, "alias", &who)?.to_string(),
            released,
            manifest_name: s(e, "manifest_name", &who)?.unwrap_or(&repo).to_string(),
            asset_prefix: s(e, "asset_prefix", &who)?.unwrap_or(&repo).to_string(),
            description: req(e, "description", &who)?.to_string(),
            ci_service: s(e, "ci_service", &who)?.unwrap_or(&service).to_string(),
            busbar_checkout: b(e, "busbar_checkout", &who, false)?,
            macos_test: s(e, "macos_test", &who)?
                .unwrap_or("cargo test --workspace --locked")
                .to_string(),
            extra_test: s(e, "extra_test", &who)?.unwrap_or("").to_string(),
            lib_only: b(e, "lib_only", &who, false)?,
            needs_prompt: s(e, "needs_prompt", &who)?.unwrap_or("").to_string(),
            needs_user: s(e, "needs_user", &who)?.unwrap_or("").to_string(),
            declares: req(e, "declares", &who)?.to_string(),
            bundle_image: s(e, "bundle_image", &who)?.unwrap_or("").to_string(),
            bundle_env: s(e, "bundle_env", &who)?.unwrap_or("").to_string(),
            keep: list(e, "keep", &who)?,
            gitignore: list(e, "gitignore", &who)?,
            notice: list(e, "notice", &who)?,
            crate_name,
            repo,
            index,
        });
    }
    Ok(Fleet {
        pin_sha: sha,
        pin_version: version,
        name_pattern,
        branches,
        plugins,
    })
}
