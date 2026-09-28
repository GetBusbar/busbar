//! The render: the files the fleet OWNS in a plugin repo, as a pure function of the registry entry,
//! the fleet pin and the templates in `.github/fleet/` (plus busbar's own LICENSE and toolchain
//! channel, which the plugins share by construction). Placeholders are `@@name@@`; a template that
//! names a placeholder the render does not define is an error, never an empty substitution.

use crate::ctx::Ctx;
use crate::fleet::registry::{Fleet, Plugin};

pub const TEMPLATE_DIR: &str = ".github/fleet";
pub const REGION_BEGIN: &str = "<!-- fleet:header:begin";
pub const REGION_END: &str = "<!-- fleet:header:end -->";

/// How a rendered file is compared and applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The file is the render, byte for byte.
    Whole,
    /// Only the block between [`REGION_BEGIN`] and [`REGION_END`] is the render; the rest of the file
    /// (a README's own body) belongs to the repo.
    Region,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub path: String,
    pub content: String,
    pub mode: Mode,
}

/// The template texts, read once.
#[derive(Debug, Clone)]
pub struct Templates {
    pub ci: String,
    pub release: String,
    pub repin: String,
    pub consumer_verify: String,
    pub toolchain: String,
    pub clippy: String,
    pub deny: String,
    pub readme_header: String,
    pub protection: String,
    pub license: String,
    /// busbar's own `rust-toolchain.toml` channel.
    pub channel: String,
}

impl Templates {
    pub fn load(cx: &Ctx) -> Result<Templates, String> {
        let t = |f: &str| cx.read(format!("{TEMPLATE_DIR}/{f}"));
        Ok(Templates {
            ci: t("ci.yml")?,
            release: t("release.yml")?,
            repin: t("repin.yml")?,
            consumer_verify: t("consumer-verify.yml")?,
            toolchain: t("rust-toolchain.toml")?,
            clippy: t("clippy.toml")?,
            deny: t("deny.toml")?,
            readme_header: t("README-header.md")?,
            protection: t("protection.json")?,
            license: cx.read("LICENSE")?,
            channel: channel_of(&cx.read("rust-toolchain.toml")?)?,
        })
    }

    /// The protection every release branch carries, as JSON.
    pub fn protection_json(&self) -> Result<serde_json::Value, String> {
        serde_json::from_str(&self.protection)
            .map_err(|e| format!("{TEMPLATE_DIR}/protection.json: {e}"))
    }
}

/// The `channel = "..."` of a rust-toolchain.toml.
pub fn channel_of(toolchain: &str) -> Result<String, String> {
    toolchain
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("channel"))
        .and_then(|rest| rest.trim_start().strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "rust-toolchain.toml names no `channel`".to_string())
}

/// A YAML double-quoted scalar (JSON string syntax is a subset of it).
fn q(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

fn yes(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

fn vars(fleet: &Fleet, p: &Plugin, channel: &str) -> Vec<(&'static str, String)> {
    vec![
        ("repo", p.repo.clone()),
        ("pin", fleet.pin_sha.clone()),
        ("version", fleet.pin_version.clone()),
        ("toolchain", channel.to_string()),
        ("kind", p.kind.clone()),
        ("alias", p.alias.clone()),
        ("crate", p.crate_name.clone()),
        ("manifest_name", p.manifest_name.clone()),
        ("asset_prefix", p.asset_prefix.clone()),
        ("description", q(&p.description)),
        ("description_md", p.description.clone()),
        ("ci_service", p.ci_service.clone()),
        ("busbar_checkout", yes(p.busbar_checkout)),
        ("macos_test", q(&p.macos_test)),
        ("extra_test", q(&p.extra_test)),
        ("lib_only", yes(p.lib_only)),
        ("needs_prompt", q(&p.needs_prompt)),
        ("needs_user", q(&p.needs_user)),
        ("declares", q(&p.declares)),
        ("bundle_image", q(&p.bundle_image)),
        ("bundle_env", q(&p.bundle_env)),
        // Daily, staggered by registry position so the fleet's schedules do not all fire at once.
        ("cron", format!("{} 9 * * *", (p.index * 7 + 3) % 60)),
    ]
}

/// Substitute every `@@name@@`; an unknown or unterminated placeholder is an error naming it.
pub fn fill(template: &str, vars: &[(&str, String)], what: &str) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(at) = rest.find("@@") {
        // `...yml@@@pin@@`: an `@` that is the literal ref separator sits right before a placeholder.
        let (lit, tail) = rest.split_at(at);
        let tail_body = &tail[2..];
        let name_end = tail_body
            .find("@@")
            .ok_or_else(|| format!("{what}: unterminated `@@` placeholder"))?;
        let name = &tail_body[..name_end];
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_lowercase() || c == b'_') {
            // Not a placeholder: emit one `@` and rescan (handles `@@@name@@`).
            out.push_str(lit);
            out.push('@');
            rest = &tail[1..];
            continue;
        }
        let value = vars
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v)
            .ok_or_else(|| format!("{what}: unknown placeholder `@@{name}@@`"))?;
        out.push_str(lit);
        out.push_str(value);
        rest = &tail_body[name_end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Everything the fleet owns in `p`'s repo, sorted by path.
pub fn render(fleet: &Fleet, p: &Plugin, t: &Templates) -> Result<Vec<Rendered>, String> {
    let v = vars(fleet, p, &t.channel);
    let whole = |path: &str, tpl: &str| -> Result<Rendered, String> {
        Ok(Rendered {
            path: path.to_string(),
            content: fill(tpl, &v, &format!("{} ({path})", p.repo))?,
            mode: Mode::Whole,
        })
    };
    let mut files = vec![
        Rendered {
            path: ".busbar-ref".into(),
            content: fleet.busbar_ref(),
            mode: Mode::Whole,
        },
        whole(".github/workflows/ci.yml", &t.ci)?,
        whole(".github/workflows/release.yml", &t.release)?,
        whole(".github/workflows/repin.yml", &t.repin)?,
        whole("rust-toolchain.toml", &t.toolchain)?,
        whole("clippy.toml", &t.clippy)?,
        whole("deny.toml", &t.deny)?,
        Rendered {
            path: "LICENSE".into(),
            content: t.license.clone(),
            mode: Mode::Whole,
        },
        Rendered {
            path: "README.md".into(),
            content: fill(&t.readme_header, &v, &format!("{} (README.md)", p.repo))?,
            mode: Mode::Region,
        },
    ];
    // A plugin that has never released has nothing for a daily consumer check to download.
    if p.released {
        files.push(whole(
            ".github/workflows/consumer-verify.yml",
            &t.consumer_verify,
        )?);
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// The managed region of a README, if it has one (begin marker line through end marker line).
pub fn region_of(text: &str) -> Option<&str> {
    let start = text.find(REGION_BEGIN)?;
    let end_rel = text[start..].find(REGION_END)?;
    let mut end = start + end_rel + REGION_END.len();
    if text[end..].starts_with('\n') {
        end += 1;
    }
    Some(&text[start..end])
}

/// A README with the managed region applied: replaced in place when present; otherwise prepended,
/// taking the place of the README's own leading `# ` title (the region carries the title).
pub fn apply_region(existing: Option<&str>, region: &str) -> String {
    match existing {
        None => region.to_string(),
        Some(text) => {
            if let Some(old) = region_of(text) {
                return text.replacen(old, region, 1);
            }
            let body = match text.split_once('\n') {
                Some((first, rest)) if first.starts_with("# ") => rest.trim_start_matches('\n'),
                _ if text.starts_with("# ") && !text.contains('\n') => "",
                _ => text,
            };
            if body.is_empty() {
                region.to_string()
            } else {
                format!("{region}\n{body}")
            }
        }
    }
}
