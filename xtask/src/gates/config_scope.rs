//! `cargo xtask gate config-scope` — THE CONFIG-TIME PROOF IS MADE ONLY AT CONFIG TIME.
//!
//! THE RULE (`docs/design/BUSBAR-1.6.0.md` THE DESIGN §11.11 R4, as the OWNER amended it
//! 2026-10-13): the host-owned bounded disk lane serves the secret kind's file source ONLY at config
//! time (boot, a config apply, a refresh), and NEVER from a request path. The proof of config time
//! is a type, `busbar_contract::config_time::ConfigScope`: a resolve that may reach a source reading
//! the disk takes `&ConfigScope`, and the one constructor is `ConfigScope::config_time()`. The type
//! holds the line only if its construction does, so this gate names every construction in the
//! workspace's production source and holds each to [`ALLOWED`], an allow-list by file AND by
//! function: the host's boot, config-apply, refresh, pre-flight and `--validate` functions, TLS
//! material's `read_pem`, and the auth chain's config load. A construction anywhere else — a
//! request path above all — is RED, naming the file, the line and the function it sits in.
//!
//! Two rows:
//! * [`ROW_SITE`]: every construction sits in an allowed (file, function);
//! * [`ROW_ALLOW`]: every allowed (file, function) still constructs one, and the scan is not blind.
//!   An allowance nobody uses is a standing permission the next request path takes; it is struck in
//!   the commit that drains it.
//!
//! A construction is any `::config_time` path segment called or taken as a value, so an aliased
//! import (`use …::ConfigScope as Proof; Proof::config_time()`) is the same construction. Test code
//! (`#[cfg(test)]`, `tests/` and `*_tests.rs` files) is not scanned: a test is not a request path.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, prove_rows_green, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan;

pub const ROW_SITE: &str = "config-scope:outside-config-time";
pub const ROW_ALLOW: &str = "config-scope:allow-list";

/// THE ALLOW-LIST: (file, the functions in it that may construct the proof). A function is named by
/// its own name, the innermost `fn` item around the construction.
pub const ALLOWED: &[(&str, &[&str])] = &[
    // Boot and every config apply build the app here.
    (
        "crates/busbar-kernel/src/appbuild.rs",
        &["build_app_from_config"],
    ),
    // The auth chain's config load (boot and reload, inside `build_app_from_config`).
    ("crates/busbar-kernel/src/auth/mod.rs", &["build", "new"]),
    ("crates/busbar-kernel/src/auth/token.rs", &["build_on"]),
    // A hook's settings, resolved at the configure push (boot / apply / hot reload).
    (
        "crates/busbar-kernel/src/hooks/mod.rs",
        &["resolve_hook_settings"],
    ),
    // Pre-flight: the operator credential, the signing keys and the secret plugins' own settings.
    (
        "crates/busbar-kernel/src/preflight.rs",
        &[
            "resolve_admin_token",
            "resolve_signing_key",
            "resolve_operator_public_key",
            "validate_builtin_secrets_resolve",
            "build_secret_resolver",
        ],
    ),
    // `--validate` and the config checks.
    (
        "crates/busbar-kernel/src/config_validate/mod.rs",
        &["validate_with_unset", "validate_providers_with"],
    ),
    // TLS material, read when the connector's `tls:` block and a plane's client identity load.
    ("crates/busbar-kernel/src/tls.rs", &["read_pem"]),
    // A door plane's members, bound when the plane loads (boot / apply).
    (
        "crates/busbar/src/root/door_steps.rs",
        &["token_exchange_binding", "member_routes"],
    ),
];

/// Below this many production files the walk has lost the workspace.
const FLOOR_FILES: usize = 500;

/// One construction: where, and the function it sits in (`""` for none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub file: String,
    pub line: usize,
    pub func: String,
}

/// Every `::config_time` path segment on a blanked line that is a construction: called, or taken
/// as a value. A module path (`config_time::ConfigScope`) and a `use` line are not.
fn constructions(counted: &str) -> usize {
    let head = counted.trim_start();
    if head.starts_with("use ")
        || head.starts_with("pub use ")
        || head.starts_with("pub(crate) use ")
    {
        return 0;
    }
    let needle = "::config_time";
    let mut n = 0;
    let mut from = 0;
    while let Some(i) = counted[from..].find(needle) {
        let end = from + i + needle.len();
        from = end;
        let next = counted[end..].chars().next();
        if next.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') {
            continue;
        }
        n += 1;
    }
    n
}

/// Every `fn` item in `lines` (blanked) as (name, first line, last line), 1-based and inclusive. A
/// body-less declaration ends in `;` and is left out.
fn fn_items(lines: &[String]) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for (i, code) in lines.iter().enumerate() {
        let mut from = 0;
        while let Some(j) = code[from..].find("fn") {
            let at = from + j;
            from = at + 2;
            let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
            if code[..at].chars().next_back().is_some_and(ident)
                || !code[at + 2..].starts_with(char::is_whitespace)
            {
                continue;
            }
            let rest = code[at + 2..].trim_start();
            let name: String = rest.chars().take_while(|c| ident(*c)).collect();
            if name.is_empty() || !rest[name.len()..].trim_start().starts_with(['(', '<']) {
                continue;
            }
            if let Some(last) = item_last_line(lines, i, at) {
                out.push((name, i + 1, last));
            }
        }
    }
    out
}

/// The 1-based line the item declared at `lines[start][col..]` closes on: its header runs to the
/// `{` at paren depth zero, its body to the brace that balances it. `None` for a declaration.
fn item_last_line(lines: &[String], start: usize, col: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut brace = 0i32;
    let mut opened = false;
    for (i, code) in lines.iter().enumerate().skip(start) {
        let from = if i == start { col } else { 0 };
        for ch in code[from..].chars() {
            match ch {
                '(' | '[' if !opened => depth += 1,
                ')' | ']' if !opened => depth -= 1,
                ';' if !opened && depth <= 0 => return None,
                '{' => {
                    if opened || depth <= 0 {
                        opened = true;
                        brace += 1;
                    }
                }
                '}' if opened => {
                    brace -= 1;
                    if brace == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// The innermost `fn` item around 1-based `line`, or `""`.
fn enclosing(items: &[(String, usize, usize)], line: usize) -> String {
    items
        .iter()
        .filter(|(_, first, last)| *first <= line && line <= *last)
        .max_by_key(|(_, first, _)| *first)
        .map_or_else(String::new, |(name, _, _)| name.clone())
}

fn is_test_file(rel: &str) -> bool {
    rel.contains("/tests/") || rel.ends_with("_tests.rs") || rel.ends_with("/tests.rs")
}

/// Every construction in the workspace's production source, and how many files were read.
pub fn scan(cx: &Ctx) -> Result<(Vec<Site>, usize), String> {
    let files = cx
        .walk(
            &WalkSpec::new(["crates"])
                .ext("rs")
                .exclude(["/tests/", "/benches/", "/examples/"]),
        )
        .map_err(|e| format!("crates: {e:?}"))?;
    let mut sites = Vec::new();
    let mut read = 0;
    for f in &files {
        let rel = f.rel_str();
        if is_test_file(&rel) {
            continue;
        }
        read += 1;
        if !f.text.contains("config_time") {
            continue;
        }
        let mut st = scan::LexState::default();
        let blanked: Vec<String> = f
            .text
            .lines()
            .map(|l| scan::blank_code(l, &mut st))
            .collect();
        let items = fn_items(&blanked);
        for sl in scan::test_scope(&f.text) {
            if sl.gated || sl.is_comment {
                continue;
            }
            for _ in 0..constructions(&sl.counted) {
                sites.push(Site {
                    file: rel.clone(),
                    line: sl.no,
                    func: enclosing(&items, sl.no),
                });
            }
        }
    }
    Ok((sites, read))
}

fn allowed(file: &str, func: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(f, fns)| *f == file && fns.contains(&func))
}

pub struct ConfigScopeGate;

impl Gate for ConfigScopeGate {
    fn name(&self) -> &'static str {
        "config-scope"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_SITE.to_string(), ROW_ALLOW.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let (sites, read) = match scan(cx) {
            Ok(s) => s,
            Err(e) => {
                return Verdict::of(vec![
                    Row::fail(ROW_SITE, "the workspace could not be walked", e.clone()),
                    Row::fail(ROW_ALLOW, "the workspace could not be walked", e),
                ])
            }
        };
        let outside: Vec<String> = sites
            .iter()
            .filter(|s| !allowed(&s.file, &s.func))
            .map(|s| {
                let func = if s.func.is_empty() {
                    "no fn".to_string()
                } else {
                    format!("fn {}", s.func)
                };
                format!("{}:{} ({func})", s.file, s.line)
            })
            .collect();
        let site_row = if outside.is_empty() {
            Row::pass(
                ROW_SITE,
                "every ConfigScope construction sits in a config-time function",
                format!(
                    "{} construction(s), each in an allowed (file, fn)",
                    sites.len()
                ),
            )
        } else {
            Row::fail(
                ROW_SITE,
                "a ConfigScope is constructed outside the config-time allow-list",
                format!(
                    "{} construction(s) outside boot, apply, refresh, pre-flight and validate (THE \
                     DESIGN §11.11 R4: a request path never holds the proof): {}",
                    outside.len(),
                    outside.join(" | ")
                ),
            )
        };
        let mut drift = Vec::new();
        if read < FLOOR_FILES {
            drift.push(format!(
                "the walk read {read} production file(s), under the floor of {FLOOR_FILES}; the \
                 scan has gone blind"
            ));
        }
        for (file, fns) in ALLOWED {
            for func in *fns {
                if !sites.iter().any(|s| s.file == *file && s.func == *func) {
                    drift.push(format!(
                        "{file} fn {func}: the allowance matched no construction — strike it"
                    ));
                }
            }
        }
        let allow_row = if drift.is_empty() {
            Row::pass(
                ROW_ALLOW,
                "every allowance names a live construction",
                format!("{read} production file(s) read"),
            )
        } else {
            Row::fail(
                ROW_ALLOW,
                "the allow-list does not say what is there",
                drift.join(" | "),
            )
        };
        Verdict::of(vec![site_row, allow_row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "this tree constructs the proof only at config time",
            &[ROW_SITE, ROW_ALLOW],
        ));

        // A REQUEST PATH CONSTRUCTING THE PROOF.
        let request = "crates/busbar-kernel/src/ingress/planted_scope.rs";
        let mut plant = Overlay::new();
        plant.set(
            request,
            "pub fn admit() {\n    let _proof = busbar_contract::config_time::ConfigScope::config_time();\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a ConfigScope constructed on a request path is RED, naming the file and the fn",
            &[ROW_SITE],
            plant,
            &[request, "fn admit"],
        ));

        // THE SAME, THROUGH AN ALIAS.
        let mut alias = Overlay::new();
        alias.set(
            request,
            "use busbar_contract::config_time::ConfigScope as Proof;\npub fn serve() {\n    let _p = Proof::config_time();\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "an aliased construction on a request path is RED",
            &[ROW_SITE],
            alias,
            &[request, "fn serve"],
        ));

        // AN ALLOWED FILE, A FUNCTION THE LIST DOES NOT NAME.
        let tls = "crates/busbar-kernel/src/tls.rs";
        let tls_text = cx.read(tls).unwrap_or_default();
        let mut wrong_fn = Overlay::new();
        wrong_fn.set(
            tls,
            format!(
                "{tls_text}\npub fn handshake() {{\n    let _p = busbar_contract::config_time::ConfigScope::config_time();\n}}\n"
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "an allowed file is allowed by function: a construction in another fn is RED",
            &[ROW_SITE],
            wrong_fn,
            &[tls, "fn handshake"],
        ));

        // AN ALLOWANCE NOBODY USES.
        let mut unused = Overlay::new();
        unused.set(
            tls,
            tls_text.replace("ConfigScope::config_time()", "ConfigScope::default()"),
        );
        report.push(prove_red(
            cx,
            self,
            "an allowance that matches no construction is RED, naming it",
            &[ROW_ALLOW],
            unused,
            &[tls, "fn read_pem"],
        ));

        // PROSE AND TEST CODE ARE NOT CONSTRUCTIONS.
        let mut prose = Overlay::new();
        prose.set(
            request,
            "// a request path never calls ConfigScope::config_time()\npub const NOTE: &str = \"ConfigScope::config_time()\";\n#[cfg(test)]\nmod t {\n    fn f() {\n        let _p = busbar_contract::config_time::ConfigScope::config_time();\n    }\n}\n",
        );
        report.push(prove_rows_green(
            cx,
            self,
            "a comment, a string literal or a #[cfg(test)] construction is not a finding",
            &[ROW_SITE],
            prose,
        ));
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_and_a_value_are_constructions_a_module_path_and_a_use_are_not() {
        assert_eq!(constructions("let s = ConfigScope::config_time();"), 1);
        assert_eq!(constructions("let f = Proof::config_time;"), 1);
        assert_eq!(
            constructions("x(&a::config_time::ConfigScope::config_time())"),
            1
        );
        assert_eq!(constructions("use busbar_contract::config_time;"), 0);
        assert_eq!(
            constructions("fn f(s: &busbar_contract::config_time::ConfigScope) {}"),
            0
        );
        assert_eq!(constructions("pub fn config_time() -> Self {"), 0);
    }

    #[test]
    fn a_construction_is_attributed_to_its_innermost_fn() {
        let lines: Vec<String> = [
            "fn outer() {",
            "    let x = 1;",
            "    fn inner() {",
            "        let _p = P::config_time();",
            "    }",
            "    let _q = P::config_time();",
            "}",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        let items = fn_items(&lines);
        assert_eq!(enclosing(&items, 4), "inner");
        assert_eq!(enclosing(&items, 6), "outer");
        assert_eq!(enclosing(&items, 8), "");
    }
}
