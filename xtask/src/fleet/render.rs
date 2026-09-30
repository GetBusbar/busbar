//! The render: the files the fleet OWNS in a plugin repo, as a pure function of the registry entry,
//! the fleet pin and the templates in `.github/fleet/` (plus busbar's own LICENSE, code of conduct
//! and toolchain channel, which the plugins share by construction). Placeholders are `@@name@@`; a
//! template that names a placeholder the render does not define is an error, never an empty
//! substitution.
//!
//! The render owns the WHOLE skeleton of a plugin repo (owner, 2026-09-30: "25 repos that are
//! TWINS"): every top-level file, the workspace `Cargo.toml` over the two crate dirs, `.github/`,
//! and the README's header region plus its fixed section headings. What a repo may hold beyond the
//! render is its two crate dirs (`<kind>-<name>/`, `<kind>-<name>-plugin/`), its `Cargo.lock`, and
//! what its registry entry declares (`keep`, `gitignore`, `notice`).

use crate::ctx::Ctx;
use crate::fleet::registry::{Fleet, Plugin};

pub const TEMPLATE_DIR: &str = ".github/fleet";
pub const REGION_BEGIN: &str = "<!-- fleet:header:begin";
pub const REGION_END: &str = "<!-- fleet:header:end -->";

/// A README heading a repo wrote before the skeleton, and the skeleton section it is.
const HEADING_ALIASES: &[(&str, &str)] = &[("Configuration", "Config"), ("Testing", "Tests")];

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
    pub readme_skeleton: String,
    pub gitignore: String,
    pub mailmap: String,
    pub workspace: String,
    pub notice: String,
    pub codecov: String,
    pub security: String,
    pub contributing: String,
    pub protection: String,
    pub license: String,
    /// busbar's own `CODE_OF_CONDUCT.md`.
    pub code_of_conduct: String,
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
            readme_skeleton: t("README-skeleton.md")?,
            gitignore: t("gitignore")?,
            mailmap: t("mailmap")?,
            workspace: t("workspace-Cargo.toml")?,
            notice: t("NOTICE")?,
            codecov: t("codecov.yml")?,
            security: t("SECURITY.md")?,
            contributing: t("CONTRIBUTING.md")?,
            protection: t("protection.json")?,
            license: cx.read("LICENSE")?,
            code_of_conduct: cx.read("CODE_OF_CONDUCT.md")?,
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

/// `1.98` of a `1.98.0` channel: the workspace's `rust-version`.
pub fn rust_version_of(channel: &str) -> Result<String, String> {
    let mut it = channel.split('.');
    match (it.next(), it.next()) {
        (Some(a), Some(b))
            if !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.bytes().all(|c| c.is_ascii_digit()) =>
        {
            Ok(format!("{a}.{b}"))
        }
        _ => Err(format!(
            "toolchain channel {channel:?} is not a `<major>.<minor>[.<patch>]` version"
        )),
    }
}

/// Lines, each newline-terminated (empty when there are none).
fn lines(v: &[String]) -> String {
    v.iter().map(|l| format!("{l}\n")).collect()
}

/// A YAML double-quoted scalar (JSON string syntax is a subset of it).
fn q(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

fn yes(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

fn vars(fleet: &Fleet, p: &Plugin, channel: &str) -> Result<Vec<(&'static str, String)>, String> {
    Ok(vec![
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
        ("stem", p.stem().to_string()),
        ("rust_version", rust_version_of(channel)?),
        ("gitignore", lines(&p.gitignore)),
        (
            "notice",
            if p.notice.is_empty() {
                String::new()
            } else {
                format!("\n{}", lines(&p.notice))
            },
        ),
    ])
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
    let v = vars(fleet, p, &t.channel)?;
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
        whole(".gitignore", &t.gitignore)?,
        whole(".mailmap", &t.mailmap)?,
        whole("Cargo.toml", &t.workspace)?,
        whole("NOTICE", &t.notice)?,
        whole("codecov.yml", &t.codecov)?,
        whole("SECURITY.md", &t.security)?,
        whole("CONTRIBUTING.md", &t.contributing)?,
        Rendered {
            path: "CODE_OF_CONDUCT.md".into(),
            content: t.code_of_conduct.clone(),
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

/// The README's fixed section skeleton for `p`, filled: every section's heading and the body a
/// fresh repo starts with.
pub fn readme_skeleton(fleet: &Fleet, p: &Plugin, t: &Templates) -> Result<String, String> {
    let v = vars(fleet, p, &t.channel)?;
    fill(
        &t.readme_skeleton,
        &v,
        &format!("{} (README skeleton)", p.repo),
    )
}

/// Whether `line` opens or closes a fenced code block.
fn is_fence(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("```") || t.starts_with("~~~")
}

/// A level-1 or level-2 ATX heading's text (`# X`, `## X`), outside a code fence.
fn top_heading(line: &str) -> Option<(usize, &str)> {
    for (level, prefix) in [(2, "## "), (1, "# ")] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return Some((level, rest.trim()));
        }
    }
    None
}

/// The `#`/`##` headings of `text`, outside code fences and outside the managed header region, as
/// written (`## Config`).
pub fn readme_headings(text: &str) -> Vec<String> {
    let body = match region_of(text) {
        Some(r) => text.replacen(r, "", 1),
        None => text.to_string(),
    };
    let mut fenced = false;
    let mut out = Vec::new();
    for line in body.lines() {
        if is_fence(line) {
            fenced = !fenced;
            continue;
        }
        if !fenced && top_heading(line).is_some() {
            out.push(line.trim_end().to_string());
        }
    }
    out
}

/// The skeleton's sections: `(heading text, default body)`, in order.
fn skeleton_sections(skeleton: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut fenced = false;
    for line in skeleton.lines() {
        if is_fence(line) {
            fenced = !fenced;
        } else if !fenced {
            if let Some((2, h)) = top_heading(line) {
                out.push((h.to_string(), String::new()));
                continue;
            }
        }
        if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// A README body (the text outside the header region) rewritten into the skeleton's sections,
/// mechanically and without dropping prose: a section whose heading is a skeleton heading (or its
/// alias) becomes that section; every other `#`/`##` heading is demoted to `###` and stays, in
/// order, inside the skeleton section it sits in (text before the first skeleton heading opens the
/// first section); a second `#` title is dropped (the header region is the title); a skeleton section the body has no text for takes the skeleton's default body.
pub fn restructure(body: &str, skeleton: &str) -> String {
    let sections = skeleton_sections(skeleton);
    if sections.is_empty() {
        return body.to_string();
    }
    let index_of = |name: &str| {
        let name = HEADING_ALIASES
            .iter()
            .find(|(from, _)| from.eq_ignore_ascii_case(name))
            .map_or(name, |(_, to)| to);
        sections
            .iter()
            .position(|(h, _)| h.eq_ignore_ascii_case(name))
    };
    let mut chunks = vec![String::new(); sections.len()];
    let mut at = 0;
    let mut fenced = false;
    for line in body.lines() {
        if is_fence(line) {
            fenced = !fenced;
        } else if !fenced {
            if let Some((level, h)) = top_heading(line) {
                // A second title: the header region carries the repo's one `#` title.
                if level == 1 {
                    continue;
                }
                match index_of(h) {
                    Some(i) => at = i,
                    None => chunks[at].push_str(&format!("### {h}\n")),
                }
                continue;
            }
        }
        chunks[at].push_str(line);
        chunks[at].push('\n');
    }
    let mut out = String::new();
    for (i, (h, default)) in sections.iter().enumerate() {
        let own = chunks[i].trim_matches('\n');
        let text = if own.trim().is_empty() {
            default.trim_matches('\n')
        } else {
            own
        };
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("## {h}\n\n{text}\n"));
    }
    out
}

/// A whole README: the header region (applied as [`apply_region`] does), then the body restructured
/// into the skeleton. A repo with no README gets the region and the skeleton's defaults.
pub fn apply_readme(existing: Option<&str>, region: &str, skeleton: &str) -> String {
    let with_region = apply_region(existing, region);
    let body = with_region.replacen(region, "", 1);
    format!("{region}\n{}", restructure(&body, skeleton))
}
