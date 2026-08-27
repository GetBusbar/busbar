// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAYER 2 of the anti-omission guard on [`super::secret_refs`]: a `SecretRef` added to a struct
//! that `secret_refs` never destructures is a TEST failure here, naming the type.
//!
//! WHY A SOURCE SCAN AND NOT A COMPILER TRICK. Layer 1 (the exhaustive destructures in
//! `secret_refs`) is enforced by the compiler, and it is strictly better where it applies: add a
//! field to `TlsCfg` and the build stops with `E0027`. But the compiler has nothing to say about a
//! `SecretRef` added to a type `secret_refs` does not mention at all, and THAT is the shape the
//! original defect had: `BrowserLoginCfg::client_secret` existed for a whole release cycle without
//! `secret_refs` ever looking at `BrowserLoginCfg`, so `--validate` printed `ok: config valid` for a
//! config whose OAuth client secret could not resolve. Rust has no reflection to close that with, so
//! the set is derived from the one place that cannot lie about it: the source.
//!
//! WHAT WOULD MAKE THIS A FALSE GREEN, and how each is closed. A scanner that finds nothing passes
//! every assertion about what it found, which is the exact failure mode this project has been burned
//! by three times (a script with no `__main__` guard that exited 0 asserting nothing; a test that
//! skipped to green when its artifact vanished; a drift gate comparing version strings while the
//! shapes diverged). So:
//!   - a missing crates directory is a PANIC, never a skip;
//!   - the scan asserts it read a plausible number of FILES and found a plausible number of
//!     DECLARATIONS before it compares anything, so a rename that silently empties the walk is red;
//!   - the inventory comparison is set EQUALITY in both directions, so neither a new type nor a
//!     stale entry passes.

use super::{SecretBearing, SECRET_BEARING_TYPES};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The repository's `crates/` directory, derived from this crate's manifest dir. Panics rather than
/// returning an `Option`: a test that cannot find the tree it is supposed to scan has FAILED to
/// determine its answer, and a check that cannot determine its answer is red, not green.
fn crates_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")); // .../crates/busbar
    let dir = manifest
        .parent()
        .unwrap_or_else(|| panic!("no parent of CARGO_MANIFEST_DIR {}", manifest.display()))
        .to_path_buf();
    assert!(
        dir.join("busbar").join("src").is_dir(),
        "expected the workspace crates/ directory at {} (containing busbar/src); the source scan \
         cannot run and must not report a pass",
        dir.display()
    );
    dir
}

/// Every `.rs` file under `crates/*/src`, EXCLUDING files that live in a `tests` directory. A test
/// file constructs config structs, it does not DECLARE them, so including them would only add
/// false positives; excluding them cannot hide a declaration, because a config struct declared in a
/// test directory is not part of the config surface `--validate` walks.
fn source_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![crates_dir()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {} failed: {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                // `target` is build output, `tests` is covered by the doc comment above.
                if name != "target" && name != "tests" {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") {
                out.push(path);
            }
        }
    }
    out
}

/// `TypeName -> the field names it declares with a `SecretRef`-mentioning type`, scanned out of the
/// sources. Deliberately a line scanner and not a Rust parser: it needs to be readable by anyone who
/// has to debug a failure, and its bias is toward OVER-reporting (a false hit is a loud, obvious
/// test failure a human resolves in one edit; a false MISS is the silent hole this whole guard
/// exists to close).
fn declared_secret_ref_fields() -> BTreeMap<String, BTreeSet<String>> {
    let struct_re = regex_lite_struct();
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let files = source_files();
    assert!(
        files.len() >= 50,
        "the source scan found only {} .rs files under crates/*/src; the walk is broken and this \
         test must not report a pass on an empty corpus",
        files.len()
    );
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {} failed: {e}", file.display()));
        let mut current: Option<String> = None;
        let mut depth: i32 = 0;
        for line in text.lines() {
            let code = strip_comment(line);
            if current.is_some() {
                depth += code.matches('{').count() as i32 - code.matches('}').count() as i32;
                if depth <= 0 {
                    current = None;
                    depth = 0;
                    continue;
                }
                if let Some(field) = field_named_secret_ref(&code) {
                    out.entry(current.clone().expect("inside a struct"))
                        .or_default()
                        .insert(field);
                }
                continue;
            }
            if let Some(name) = struct_re(&code) {
                current = Some(name);
                depth = code.matches('{').count() as i32 - code.matches('}').count() as i32;
                if depth <= 0 {
                    // A tuple struct or a one-line `struct X;` declares no named fields.
                    current = None;
                    depth = 0;
                }
            }
        }
    }
    out
}

/// The code content of a line: empty for a whole-line `//` comment, and with a trailing `//` comment
/// removed when the line holds no string literal (so a `//` inside a literal cannot truncate code).
fn strip_comment(line: &str) -> String {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return String::new();
    }
    if line.contains('"') {
        return line.to_string();
    }
    match line.find("//") {
        Some(i) => line[..i].to_string(),
        None => line.to_string(),
    }
}

/// `struct Foo` on a declaration line -> `Some("Foo")`. Matches any visibility and skips a line that
/// merely MENTIONS the word (a `use` or a turbofish), by requiring `struct` to start the item.
fn regex_lite_struct() -> impl Fn(&str) -> Option<String> {
    |code: &str| {
        let t = code.trim_start();
        let t = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub(super) "))
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);
        let rest = t.strip_prefix("struct ")?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some(name)
    }
}

/// `pub(crate) client_secret: Option<SecretRef>,` -> `Some("client_secret")`. Requires a `name:`
/// prefix so a method signature, a `where` clause or a struct-literal line cannot match.
fn field_named_secret_ref(code: &str) -> Option<String> {
    if !code.contains("SecretRef") {
        return None;
    }
    let t = code.trim_start();
    let t = t
        .strip_prefix("pub(crate) ")
        .or_else(|| t.strip_prefix("pub(super) "))
        .or_else(|| t.strip_prefix("pub "))
        .unwrap_or(t);
    let (name, ty) = t.split_once(':')?;
    let name = name.trim();
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    // `foo: SecretRef` / `Option<SecretRef>` / `Vec<SecretRef>` / `BTreeMap<String, SecretRef>` all
    // count: the guard is about the TYPE appearing in a field position, at any nesting.
    ty.contains("SecretRef").then(|| name.to_string())
}

/// The substring of `path` from the first occurrence of `from` up to (not including) `to`. Both
/// markers must be present or the extraction PANICS: a scan that cannot find the region it is
/// supposed to read has FAILED to determine its answer, and a check that cannot determine its answer
/// is red, not green.
fn read_between(path: &Path, from: &str, to: &str) -> String {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let start = text
        .find(from)
        .unwrap_or_else(|| panic!("`{from}` is not in {}", path.display()));
    let end = text[start..]
        .find(to)
        .unwrap_or_else(|| panic!("`{to}` is not in {}", path.display()));
    text[start..start + end].to_string()
}

/// The brace-balanced text of an `impl` block, from its `header` line to the `}` that closes it.
/// Panics if the header is absent or the braces never balance — the same fail-loud contract as
/// [`read_between`], because a plane whose `secret_refs` impl the scan could not locate is a plane
/// whose Walked types would go unchecked.
fn extract_impl_block(path: &Path, header: &str) -> String {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {} failed: {e}", path.display()));
    let start = text
        .find(header)
        .unwrap_or_else(|| panic!("`{header}` is not in {}", path.display()));
    let rest = &text[start..];
    let open = rest
        .find('{')
        .unwrap_or_else(|| panic!("`{header}` has no opening brace in {}", path.display()));
    let mut depth = 0i32;
    for (i, ch) in rest[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return rest[..open + i + 1].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("`{header}` block never closes in {}", path.display());
}

/// The body of `secret_refs`, the helpers it delegates its destructures to, AND the per-plane
/// `PlaneCfg::secret_refs` impls the MCP and A2A sweeps now live in. Used to prove that a type
/// CLAIMING to be `Walked` really is destructured somewhere this guard can see, so the inventory
/// cannot be satisfied by listing a type and never looking at it.
///
/// The plane impls are folded in because that is where the exhaustive destructures for the A2A and
/// MCP credential types moved: the core walk stopped naming `TokenExchangeCfg`, `OutboundCredential`
/// and `ClientIdentityCfg` and now loops the trait, so `secret_refs.rs` alone would report those
/// Walked types as undestructured — a false red that is really "look in the impl". This concatenation
/// is what makes the Walked assertions track the destructure to wherever the plane put it.
fn secret_refs_source() -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let core = read_between(
        &src.join("config_validate").join("secret_refs.rs"),
        "pub(crate) fn secret_refs(",
        "pub(crate) const SECRET_BEARING_TYPES",
    );
    // The MCP plane's `tools:` config moved to the `busbar-mcp` crate (Phase-B B2); its `secret_refs`
    // impl names the `PlaneCfg` trait through its public path from there. The trait itself relocated
    // to `busbar-substrate` (Phase-C config-seam), so the impl now spells `busbar_substrate::…` and
    // the scan matches on that spelling.
    let mcp = extract_impl_block(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("busbar-mcp")
            .join("src")
            .join("mcp")
            .join("config.rs"),
        "impl busbar_substrate::plane::config::PlaneCfg for ToolsCfg",
    );
    let a2a = extract_impl_block(
        &src.join("a2a").join("config.rs"),
        "impl busbar_substrate::plane::config::PlaneCfg for AgentsCfg",
    );
    let body = format!("{core}\n{mcp}\n{a2a}");
    assert!(
        body.len() > 500,
        "the extracted secret_refs region is only {} bytes; the extraction is broken and the \
         Walked assertions below would pass vacuously",
        body.len()
    );
    body
}

/// EVERY type in the tree that declares a `SecretRef`-typed field is accounted for by
/// [`SECRET_BEARING_TYPES`] — set equality in both directions.
///
/// A NEW secret-bearing type fails here with its name. A type that stops carrying secrets fails here
/// too, as a stale entry, so the inventory can never accumulate standing permission for a type that
/// no longer exists.
#[test]
fn every_secret_bearing_type_is_accounted_for() {
    let declared = declared_secret_ref_fields();
    assert!(
        declared.len() >= 6,
        "the source scan found only {} types declaring a SecretRef field ({:?}); busbar has had at \
         least six since 1.5.3, so the scanner is broken and must not report a pass",
        declared.len(),
        declared.keys().collect::<Vec<_>>()
    );
    let found: BTreeSet<&str> = declared.keys().map(String::as_str).collect();
    let inventoried: BTreeSet<&str> = SECRET_BEARING_TYPES.iter().map(|(t, _)| *t).collect();
    assert_eq!(
        SECRET_BEARING_TYPES.len(),
        inventoried.len(),
        "SECRET_BEARING_TYPES lists a type twice"
    );

    let unaccounted: Vec<&&str> = found.difference(&inventoried).collect();
    assert!(
        unaccounted.is_empty(),
        "these types declare a `SecretRef` field but are NOT in \
         config_validate::SECRET_BEARING_TYPES: {unaccounted:?}\n\nA secret busbar cannot enumerate \
         is a secret `--validate` reports as fine and then fails on at runtime. Walk the type in \
         `secret_refs` (exhaustive destructure, no `..`) and add it to the inventory as `Walked`, \
         or, if it is a deserialize-side shape that is lowered into a walked type before any \
         validation runs, add it as `NotInResolvedConfig` with that reason. Fields seen: {:?}",
        declared
            .iter()
            .filter(|(t, _)| unaccounted.contains(&&t.as_str()))
            .collect::<Vec<_>>()
    );

    let stale: Vec<&&str> = inventoried.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "these types are in SECRET_BEARING_TYPES but no longer declare a `SecretRef` field: \
         {stale:?}. Remove them; a stale inventory entry is standing permission for a future type \
         to reuse the name unchecked."
    );
}

/// A type the inventory calls `Walked` is REALLY destructured by `secret_refs`, and a type it calls
/// `NotInResolvedConfig` really is absent from it. Without this, the inventory would be satisfiable
/// by writing a name down, which is precisely the "remembered, not enforced" property B1 was.
#[test]
fn the_inventory_matches_what_secret_refs_actually_does() {
    let body = secret_refs_source();
    let mut walked = 0;
    let mut excluded = 0;
    for (ty, bearing) in SECRET_BEARING_TYPES {
        let destructured = body.contains(&format!("{ty} {{"));
        match bearing {
            SecretBearing::Walked => {
                assert!(
                    destructured,
                    "SECRET_BEARING_TYPES calls `{ty}` Walked, but `secret_refs` never \
                     destructures it (`{ty} {{`). Either walk it or reclassify it."
                );
                walked += 1;
            }
            SecretBearing::NotInResolvedConfig(reason) => {
                assert!(
                    !destructured,
                    "SECRET_BEARING_TYPES calls `{ty}` unreachable from RootCfg (\"{reason}\"), but \
                     `secret_refs` destructures it. Reclassify it as Walked."
                );
                assert!(
                    reason.len() > 20,
                    "`{ty}` is excluded with no real reason (\"{reason}\"). An exclusion without a \
                     stated reason is a waiver, and there are none."
                );
                excluded += 1;
            }
        }
    }
    assert!(
        walked >= 6 && excluded >= 1,
        "the inventory checked {walked} walked and {excluded} excluded types; that is fewer than \
         busbar has, so this test ran vacuously"
    );
}

/// The behavioural half, at the level `--validate` actually asks: a config carrying a
/// `browser_login.client_secret` yields that path from `secret_refs`. This is the reference the old
/// hand-written list missed, and this test fails against the pre-fix function.
#[test]
fn browser_login_client_secret_is_enumerated() {
    let yaml = r#"
listen: "127.0.0.1:8080"
public_url: "https://busbar.example.com"
providers: {}
models: {}
identity-providers:
  corp-oidc:
    module: oidc
    browser_login:
      client_id: busbar-web
      client_secret: { env: BUSBAR_TEST_OIDC_CLIENT_SECRET }
auth:
  chain: []
  admin_auth: []
"#;
    let deploy: crate::config::DeployCfg =
        serde_yaml::from_str(yaml).expect("the fixture DeployCfg yaml must parse");
    let cfg = crate::config::resolve(&deploy, &std::collections::HashMap::new())
        .expect("the fixture config must resolve");

    let paths: Vec<String> = super::secret_refs(&cfg)
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert!(
        paths.contains(&"identity-providers.corp-oidc.browser_login.client_secret".to_string()),
        "secret_refs did not enumerate the OAuth confidential-client secret; --validate would \
         report `ok: config valid` for a config whose client_secret cannot resolve. Got: {paths:?}"
    );
}
