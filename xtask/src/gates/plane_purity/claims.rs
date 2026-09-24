//! THE FROZEN-WIRE CLAIM CHECK — a pragma's back-compat claim is verified against the released tag
//! it names, or the pragma is refused.
//!
//! WHY IT EXISTS. The frozen-wire carve-out exempts a neutral line from the vocabulary rows on the
//! strength of ONE sentence: the reason. Nothing ever read that sentence. Eleven pragmas in core
//! exempted the `mcp:` key, `McpEndpointSection` and the `mcp`/`tools`/`agents`/`streams`/
//! `decisions`/`oauth_as` top-level keys as "frozen since 1.5.3" — and `v1.5.3` and `v1.5.5` both
//! carry a 26-field `DeployCfg` in which NONE of those keys exists (item 2). They were 1.6.0-additive
//! names wearing a back-compat exemption, and the gate honoured every one of them.
//!
//! THE RULE. A frozen-wire pragma is a back-compat claim, so it must be a CHECKABLE one:
//!
//! * it states `frozen since X.Y.Z` — the release whose shipped grammar it is protecting;
//! * it names at least one wire key as `key:` (backticks allowed) — the thing that is frozen;
//! * the config-surface fingerprint AT TAG `vX.Y.Z` (read from history through [`Ctx::git_show`],
//!   never from the working tree, which the same commit is free to edit) carries every named key as
//!   a field of some type, and every CamelCase type the reason names as a type.
//!
//! A pragma that fails any of the three is RED on [`super::ROW_FROZEN_WIRE_CLAIM`]. A tag that does
//! not resolve, or resolves to no fingerprint, is RED too — an unverifiable claim is not a verified
//! one, and "since 9.9.9" must not be the way round the check.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::ctx::{Ctx, SourceFile};
use crate::gates::config_schema::SNAPSHOT_HOMES;
use crate::ledger::Row;

/// One frozen-wire pragma as it sits in a neutral source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pragma {
    pub file: String,
    pub line: usize,
    pub reason: String,
}

impl Pragma {
    fn site(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
}

/// The reason text of a REASONED frozen-wire pragma on `raw`, or `None`. The same acceptance as
/// [`super::scanner::has_frozen_wire_pragma`] — a bare marker is not a pragma and claims nothing.
pub fn pragma_reason(raw: &str) -> Option<String> {
    let mut rest = raw;
    while let Some(i) = rest.find("plane-purity:") {
        let tail = rest[i + "plane-purity:".len()..].trim_start_matches([' ', '\t']);
        if let Some(after) = tail.strip_prefix("frozen-wire") {
            let trimmed = after.trim_start_matches([' ', '\t']);
            if after.len() != trimmed.len() && !trimmed.is_empty() {
                return Some(trimmed.trim_end().to_string());
            }
        }
        rest = &rest[i + 1..];
    }
    None
}

/// Every reasoned frozen-wire pragma in `files`, production and test scope alike: the carve-out
/// is honoured in both, so its claim is owed in both.
pub fn collect(files: &[SourceFile]) -> Vec<Pragma> {
    let mut out = Vec::new();
    for f in files {
        let rel = f.rel_str();
        for (idx, raw) in f.text.lines().enumerate() {
            if let Some(reason) = pragma_reason(raw) {
                out.push(Pragma {
                    file: rel.clone(),
                    line: idx + 1,
                    reason,
                });
            }
        }
    }
    out
}

/// `frozen since X.Y.Z` → `X.Y.Z`.
pub fn since_version(reason: &str) -> Option<String> {
    let lc = reason.to_ascii_lowercase();
    let i = lc.find("frozen since")?;
    let tail = reason[i + "frozen since".len()..].trim_start();
    let tail = tail.strip_prefix('v').unwrap_or(tail);
    let ver: String = tail
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let ver = ver.trim_end_matches('.').to_string();
    let parts: Vec<&str> = ver.split('.').collect();
    (parts.len() == 3 && parts.iter().all(|p| !p.is_empty())).then_some(ver)
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'
}

/// The wire keys a reason names, spelled `key:` — a lowercase identifier (hyphens allowed, as in
/// `identity-providers:`) immediately followed by a colon that ends the token.
pub fn named_keys(reason: &str) -> Vec<String> {
    let chars: Vec<char> = reason.chars().collect();
    let mut out = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        if c != ':' {
            continue;
        }
        let after_ok = chars
            .get(i + 1)
            .is_none_or(|n| n.is_whitespace() || matches!(n, '`' | ')' | ',' | ';' | '.'));
        if !after_ok {
            continue;
        }
        let mut s = i;
        while s > 0 && is_key_char(chars[s - 1]) {
            s -= 1;
        }
        if s == i || !chars[s].is_ascii_lowercase() {
            continue;
        }
        if s > 0 && (chars[s - 1].is_ascii_alphanumeric() || chars[s - 1] == '_') {
            continue;
        }
        let key: String = chars[s..i].iter().collect();
        if !out.contains(&key) {
            out.push(key);
        }
    }
    out
}

/// The CamelCase type names a reason names: an identifier that starts uppercase and carries at
/// least one lowercase letter and a second uppercase letter (`McpEndpointSection`, `DeployCfg`).
/// An ordinary capitalised English word has one hump and is not a type claim.
pub fn named_types(reason: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in reason.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        let mut cs = tok.chars();
        let Some(first) = cs.next() else { continue };
        if !first.is_ascii_uppercase() {
            continue;
        }
        let uppers = tok.chars().filter(|c| c.is_ascii_uppercase()).count();
        let lowers = tok.chars().filter(|c| c.is_ascii_lowercase()).count();
        if uppers >= 2 && lowers >= 1 && !out.iter().any(|t| t == tok) {
            out.push(tok.to_string());
        }
    }
    out
}

/// The config surface a released tag shipped: its type names and the union of every type's fields.
#[derive(Debug, Clone, Default)]
pub struct Surface {
    pub home: String,
    pub types: BTreeSet<String>,
    pub fields: BTreeSet<String>,
}

/// Parse one fingerprint document.
pub fn surface_of(home: &str, text: &str) -> Result<Surface, String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("{home}: not JSON ({e})"))?;
    let types = doc
        .get("types")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{home}: carries no `types` map"))?;
    if types.is_empty() {
        return Err(format!("{home}: carries an EMPTY `types` map"));
    }
    let mut s = Surface {
        home: home.to_string(),
        ..Surface::default()
    };
    for (name, def) in types {
        s.types.insert(name.clone());
        if let Some(fields) = def.get("fields").and_then(Value::as_object) {
            s.fields.extend(fields.keys().cloned());
        }
    }
    Ok(s)
}

/// The fingerprint at `vVER`, read from history at whichever home the tag carries it.
fn surface_at(cx: &Ctx, ver: &str) -> Result<Surface, String> {
    let tag = format!("v{ver}");
    let mut errs = Vec::new();
    for home in SNAPSHOT_HOMES {
        match cx.git_show(&tag, home) {
            Ok(text) => return surface_of(home, &text).map_err(|e| format!("{tag}:{e}")),
            Err(e) => errs.push(format!("{home}: {}", e.trim())),
        }
    }
    Err(format!(
        "tag {tag} carries no config-surface fingerprint at any home ({})",
        errs.join("; ")
    ))
}

/// Judge one pragma against the surface its claim names. `Ok(evidence)` or `Err(why)`.
fn judge(
    p: &Pragma,
    surfaces: &mut BTreeMap<String, Result<Surface, String>>,
    cx: &Ctx,
) -> Result<String, String> {
    let Some(ver) = since_version(&p.reason) else {
        return Err(format!(
            "{} states no `frozen since X.Y.Z` — a frozen-wire exemption is a back-compat claim and \
             an unstated release is an unverifiable one",
            p.site()
        ));
    };
    let keys = named_keys(&p.reason);
    if keys.is_empty() {
        return Err(format!(
            "{} names no wire key as `key:` — the claim does not say WHAT is frozen",
            p.site()
        ));
    }
    let surface = surfaces
        .entry(ver.clone())
        .or_insert_with(|| surface_at(cx, &ver));
    let surface = match surface {
        Ok(s) => s,
        Err(e) => return Err(format!("{} claims frozen since {ver}, but {e}", p.site())),
    };
    let absent_keys: Vec<&String> = keys
        .iter()
        .filter(|k| !surface.fields.contains(*k))
        .collect();
    let absent_types: Vec<String> = named_types(&p.reason)
        .into_iter()
        .filter(|t| !surface.types.contains(t))
        .collect();
    if !absent_keys.is_empty() || !absent_types.is_empty() {
        let mut named: Vec<String> = absent_keys.iter().map(|k| format!("{k}:")).collect();
        named.extend(absent_types);
        return Err(format!(
            "{} claims frozen since {ver}, but v{ver} ({}) carries no {} — a key absent at the tag \
             it claims is not back-compat, it is debt wearing an exemption",
            p.site(),
            surface.home,
            named.join(", ")
        ));
    }
    Ok(format!(
        "{} (v{ver}: {})",
        p.site(),
        keys.iter()
            .map(|k| format!("{k}:"))
            .collect::<Vec<_>>()
            .join(" ")
    ))
}

/// The row: every frozen-wire pragma's claim is verified at its tag.
pub fn row(cx: &Ctx, id: &str, pragmas: &[Pragma]) -> Row {
    let title = "every frozen-wire pragma's back-compat claim holds at the tag it names";
    let mut surfaces = BTreeMap::new();
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for p in pragmas {
        match judge(p, &mut surfaces, cx) {
            Ok(ev) => ok.push(ev),
            Err(why) => bad.push(why),
        }
    }
    if bad.is_empty() {
        Row::pass(
            id,
            title,
            format!("{} pragma(s) verified: {}", ok.len(), ok.join(" ")),
        )
    } else {
        Row::fail(
            id,
            "a frozen-wire pragma's back-compat claim is false or unverifiable",
            format!(
                "{} of {} pragma(s) refused: {}",
                bad.len(),
                pragmas.len(),
                bad.join(" | ")
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_claim_keys_and_types() {
        let r = pragma_reason(
            "pub mcp: X, // plane-purity: frozen-wire the mcp: top-level wire key + \
             McpEndpointSection snapshot type (frozen since 1.5.3)",
        )
        .unwrap();
        assert_eq!(since_version(&r).as_deref(), Some("1.5.3"));
        assert_eq!(named_keys(&r), vec!["mcp".to_string()]);
        assert_eq!(named_types(&r), vec!["McpEndpointSection".to_string()]);
        assert_eq!(
            named_keys("the omitted-`protocol:` default"),
            vec!["protocol".to_string()]
        );
        assert!(pragma_reason("// plane-purity: frozen-wire").is_none());
        assert!(since_version("frozen since 1.5").is_none());
    }

    #[test]
    fn a_key_absent_from_the_tag_surface_is_absent() {
        let s = surface_of(
            "snap",
            r#"{"types":{"DeployCfg":{"fields":{"providers":{}}},"ProviderCfg":{"fields":{"protocol":{}}}}}"#,
        )
        .unwrap();
        assert!(s.fields.contains("protocol"));
        assert!(!s.fields.contains("mcp"));
        assert!(!s.types.contains("McpEndpointSection"));
        assert!(surface_of("snap", r#"{"types":{}}"#).is_err());
    }
}
