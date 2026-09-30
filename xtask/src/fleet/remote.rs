//! What the checker reads about a repo, behind a trait so a test can plant any drift. [`Gh`] is
//! the real one: the `gh` CLI (its token, its pagination), GetBusbar only.

use std::process::Command;

use serde_json::Value;

pub const ORG: &str = "GetBusbar";

/// A repo's own settings, as the fleet norm reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `public` / `private` / `internal`.
    pub visibility: String,
    /// The SPDX id GitHub detects from the LICENSE file (`none` when it detects none).
    pub license: String,
    pub default_branch: String,
}

pub trait Remote {
    /// The repo's visibility, detected license and default branch.
    fn settings(&self, repo: &str) -> Result<Settings, String>;
    /// Every file path on `branch` (blobs only).
    fn files(&self, repo: &str, branch: &str) -> Result<Vec<String>, String>;
    /// A file's text on `branch`; `None` when it does not exist.
    fn read(&self, repo: &str, branch: &str, path: &str) -> Result<Option<String>, String>;
    /// Every branch name.
    fn branches(&self, repo: &str) -> Result<Vec<String>, String>;
    /// The branch's protection as GitHub reports it; `None` when the branch is unprotected.
    fn protection(&self, repo: &str, branch: &str) -> Result<Option<Value>, String>;
}

/// The `gh` CLI.
pub struct Gh;

pub fn gh(args: &[&str]) -> Result<(bool, String, String), String> {
    let out = Command::new("gh")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run `gh`: {e}"))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn not_found(stdout: &str, stderr: &str) -> bool {
    let both = format!("{stdout}{stderr}");
    both.contains("HTTP 404")
        || both.contains("\"status\":\"404\"")
        || both.contains("Not Found")
        || both.contains("Branch not protected")
}

impl Remote for Gh {
    fn settings(&self, repo: &str) -> Result<Settings, String> {
        let api = format!("repos/{ORG}/{repo}");
        let (ok, out, err) = gh(&["api", &api])?;
        if !ok {
            return Err(format!("`gh api {api}`: {}", err.trim()));
        }
        let v: Value = serde_json::from_str(&out).map_err(|e| format!("{api}: {e}"))?;
        let field = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("{api}: no `{k}`"))
        };
        Ok(Settings {
            visibility: field("visibility")?,
            license: v
                .get("license")
                .and_then(|l| l.get("spdx_id"))
                .and_then(Value::as_str)
                .unwrap_or("none")
                .to_string(),
            default_branch: field("default_branch")?,
        })
    }

    fn files(&self, repo: &str, branch: &str) -> Result<Vec<String>, String> {
        let path = format!("repos/{ORG}/{repo}/git/trees/{branch}?recursive=1");
        let (ok, out, err) = gh(&["api", &path])?;
        if !ok {
            return Err(format!("`gh api {path}`: {}", err.trim()));
        }
        let v: Value = serde_json::from_str(&out).map_err(|e| format!("{path}: {e}"))?;
        if v.get("truncated").and_then(Value::as_bool) == Some(true) {
            return Err(format!("{path}: the tree listing is truncated; a partial listing cannot rule out an unmanaged file"));
        }
        Ok(v.get("tree")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{path}: no `tree` array"))?
            .iter()
            .filter(|e| e.get("type").and_then(Value::as_str) == Some("blob"))
            .filter_map(|e| e.get("path").and_then(Value::as_str).map(str::to_string))
            .collect())
    }

    fn read(&self, repo: &str, branch: &str, path: &str) -> Result<Option<String>, String> {
        let api = format!("repos/{ORG}/{repo}/contents/{path}?ref={branch}");
        let (ok, out, err) = gh(&["api", "-H", "Accept: application/vnd.github.raw", &api])?;
        if ok {
            Ok(Some(out))
        } else if not_found(&out, &err) {
            Ok(None)
        } else {
            Err(format!("`gh api {api}`: {}", err.trim()))
        }
    }

    fn branches(&self, repo: &str) -> Result<Vec<String>, String> {
        let api = format!("repos/{ORG}/{repo}/branches?per_page=100");
        let (ok, out, err) = gh(&["api", "--paginate", &api, "--jq", ".[].name"])?;
        if !ok {
            return Err(format!("`gh api {api}`: {}", err.trim()));
        }
        let names: Vec<String> = out
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        if names.is_empty() {
            return Err(format!(
                "`gh api {api}` listed no branches; an empty answer is not an empty repo"
            ));
        }
        Ok(names)
    }

    fn protection(&self, repo: &str, branch: &str) -> Result<Option<Value>, String> {
        let api = format!("repos/{ORG}/{repo}/branches/{branch}/protection");
        let (ok, out, err) = gh(&["api", &api])?;
        if ok {
            serde_json::from_str(&out)
                .map(Some)
                .map_err(|e| format!("{api}: {e}"))
        } else if not_found(&out, &err) {
            Ok(None)
        } else {
            Err(format!(
                "`gh api {api}`: {} (reading protection needs an admin token)",
                err.trim()
            ))
        }
    }
}

/// GitHub's GET shape of a protection, reduced to the PUT shape `.github/fleet/protection.json` is
/// written in, so the two compare as values. Keys the PUT does not set are dropped; `enabled`
/// wrappers are unwrapped; required contexts are sorted.
pub fn normalize_protection(got: &Value) -> Value {
    let flag = |k: &str| {
        got.get(k)
            .map(|v| v.get("enabled").cloned().unwrap_or_else(|| v.clone()))
            .unwrap_or(Value::Bool(false))
    };
    let checks = got
        .get("required_status_checks")
        .filter(|v| !v.is_null())
        .map(|rsc| {
            let mut contexts: Vec<String> = rsc
                .get("contexts")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            contexts.sort();
            serde_json::json!({
                "strict": rsc.get("strict").cloned().unwrap_or(Value::Bool(false)),
                "contexts": contexts,
            })
        });
    let reviews = got.get("required_pull_request_reviews").filter(|v| !v.is_null()).map(|r| {
        serde_json::json!({
            "dismiss_stale_reviews": r.get("dismiss_stale_reviews").cloned().unwrap_or(Value::Bool(false)),
            "require_code_owner_reviews": r.get("require_code_owner_reviews").cloned().unwrap_or(Value::Bool(false)),
            "required_approving_review_count": r.get("required_approving_review_count").cloned().unwrap_or(Value::from(0)),
            "require_last_push_approval": r.get("require_last_push_approval").cloned().unwrap_or(Value::Bool(false)),
        })
    });
    let restrictions = got
        .get("restrictions")
        .filter(|v| !v.is_null())
        .map(|_| Value::String("restricted".into()))
        .unwrap_or(Value::Null);
    serde_json::json!({
        "required_status_checks": checks.unwrap_or(Value::Null),
        "enforce_admins": flag("enforce_admins"),
        "required_pull_request_reviews": reviews.unwrap_or(Value::Null),
        "restrictions": restrictions,
        "required_linear_history": flag("required_linear_history"),
        "allow_force_pushes": flag("allow_force_pushes"),
        "allow_deletions": flag("allow_deletions"),
        "block_creations": flag("block_creations"),
        "required_conversation_resolution": flag("required_conversation_resolution"),
        "lock_branch": flag("lock_branch"),
        "allow_fork_syncing": flag("allow_fork_syncing"),
    })
}

/// The spec with its contexts sorted, so it compares against [`normalize_protection`].
pub fn normalize_spec(spec: &Value) -> Value {
    let mut s = spec.clone();
    if let Some(a) = s
        .get_mut("required_status_checks")
        .and_then(|r| r.get_mut("contexts"))
        .and_then(Value::as_array_mut)
    {
        a.sort_by(|x, y| x.as_str().cmp(&y.as_str()));
    }
    s
}
