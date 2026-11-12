//! Existing plugin checks and canonical scaffolding under trusted native
//! admission (former `native_plugins`).
use super::sp::{self, R, at, need, runtime, value_error, violation};
use super::{Q, git, native_settings, product, pysteps, sanitizer};
use crate::json::{self, Value, object};
use std::path::{Path, PathBuf};

fn suffix() -> &'static str {
    if cfg!(target_os = "macos") {
        ".dylib"
    } else {
        ".so"
    }
}

/// The repository-owned required extra selection from the trusted fleet
/// registry (`yaml.safe_load(plugins.yaml)['plugins']`). Only the block
/// sequence of plain/quoted/literal scalars that registry uses is accepted;
/// anything else for the selected entry refuses rather than guessing.
pub fn registered_extra_test(text: &str, repo: &str) -> R<Option<String>> {
    let lines: Vec<&str> = text.split('\n').collect();
    let start = lines
        .iter()
        .position(|l| l.trim_end() == "plugins:")
        .ok_or_else(|| sp::key_error("plugins"))?;
    let mut items: Vec<Vec<(String, usize)>> = Vec::new();
    let mut sequence_indent = None;
    let mut i = start + 1;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            i += 1;
            continue;
        }
        let indent = line.len() - trimmed.len();
        if indent == 0 {
            break;
        }
        let entry = trimmed
            .strip_prefix("- ")
            .filter(|_| *sequence_indent.get_or_insert(indent) == indent);
        if let Some(rest) = entry {
            items.push(Vec::new());
            let key_column = indent + 2;
            items
                .last_mut()
                .unwrap()
                .push((format!("{}{rest}", " ".repeat(key_column)), i));
        } else if let Some(item) = items.last_mut() {
            item.push((line.to_owned(), i));
        }
        i += 1;
    }
    for item in items {
        let key_indent = item
            .first()
            .map(|(l, _)| l.len() - l.trim_start().len())
            .unwrap_or(0);
        let mut fields: Vec<(String, String, usize)> = Vec::new();
        for (line, number) in &item {
            let indent = line.len() - line.trim_start().len();
            if indent != key_indent {
                continue;
            }
            let body = line.trim_start();
            if let Some((key, value)) = body.split_once(':')
                && !key.is_empty()
                && key
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                && (value.is_empty() || value.starts_with(' '))
            {
                fields.push((key.to_owned(), value.trim().to_owned(), *number));
            }
        }
        let value_of = |key: &str| fields.iter().find(|(k, _, _)| k == key);
        let Some((_, name, _)) = value_of("repo") else {
            return Err(sp::key_error("repo"));
        };
        if scalar(name, &lines, 0, key_indent)? != repo {
            continue;
        }
        return match value_of("extra_test") {
            None => Ok(None),
            Some((_, raw, number)) => Ok(Some(scalar(raw, &lines, *number, key_indent)?)),
        };
    }
    Ok(None)
}

/// One YAML scalar: plain (single line), single/double quoted (single line)
/// or a `|`/`|-`/`|+` literal block.
fn scalar(raw: &str, lines: &[&str], number: usize, key_indent: usize) -> R<String> {
    let unsupported = || value_error("unsupported plugin registry scalar");
    if let Some(chomp) = raw.strip_prefix('|') {
        let chomp = chomp.split(" #").next().unwrap_or("").trim();
        if !matches!(chomp, "" | "-" | "+") {
            return Err(unsupported());
        }
        let mut block: Vec<&str> = Vec::new();
        let mut indent = None;
        for line in &lines[number + 1..] {
            let trimmed = line.trim_start();
            let here = line.len() - trimmed.len();
            if trimmed.is_empty() {
                block.push("");
                continue;
            }
            let wanted = *indent.get_or_insert(here);
            if here <= key_indent || here < wanted {
                break;
            }
            block.push(&line[wanted..]);
        }
        let mut text = block.join("\n");
        let body = text.trim_end_matches('\n').to_owned();
        text = match chomp {
            "-" => body,
            "+" => format!("{text}\n"),
            _ => format!("{body}\n"),
        };
        return Ok(text);
    }
    if let Some(rest) = raw.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        loop {
            match chars.next() {
                None => return Err(unsupported()),
                Some('"') => break,
                Some('\\') => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('0') => out.push('\0'),
                    Some(' ') => out.push(' '),
                    Some('e') => out.push('\x1b'),
                    Some('x') => {
                        let hex: String = chars.by_ref().take(2).collect();
                        out.push(
                            u32::from_str_radix(&hex, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or_else(unsupported)?,
                        );
                    }
                    Some('u') => {
                        let hex: String = chars.by_ref().take(4).collect();
                        out.push(
                            u32::from_str_radix(&hex, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or_else(unsupported)?,
                        );
                    }
                    _ => return Err(unsupported()),
                },
                Some(c) => out.push(c),
            }
        }
        let tail: String = chars.collect();
        let tail = tail.trim();
        if !(tail.is_empty() || tail.starts_with('#')) {
            return Err(unsupported());
        }
        return Ok(out);
    }
    if let Some(rest) = raw.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = rest.chars().peekable();
        loop {
            match chars.next() {
                None => return Err(unsupported()),
                Some('\'') if chars.peek() == Some(&'\'') => {
                    chars.next();
                    out.push('\'');
                }
                Some('\'') => break,
                Some(c) => out.push(c),
            }
        }
        let tail: String = chars.collect();
        let tail = tail.trim();
        if !(tail.is_empty() || tail.starts_with('#')) {
            return Err(unsupported());
        }
        return Ok(out);
    }
    let plain = match raw.find(" #") {
        Some(i) => &raw[..i],
        None => raw,
    }
    .trim();
    if plain.starts_with(['[', '{', '&', '*', '!', '>', '%', '@', '`']) {
        return Err(unsupported());
    }
    if let Some(next) = lines.get(number + 1) {
        let trimmed = next.trim_start();
        let indent = next.len() - trimmed.len();
        if number > 0
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && indent > key_indent
            && !trimmed.starts_with("- ")
        {
            return Err(unsupported());
        }
    }
    Ok(plain.to_owned())
}

pub fn qualify_plugin(q: &mut Q, _host: &Path, sdk: &Path) -> R<()> {
    let entry = at(at(&q.policy, "repositories")?, &q.repository)?.clone();
    if entry.at("language").as_str() == Some("c") {
        return qualify_c(q, &entry, sdk);
    }
    q.run("fmt", sp::strings(&["cargo", "fmt", "--all", "--check"]))?;
    q.run(
        "clippy",
        sp::strings(&[
            "cargo",
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ]),
    )?;
    let meta_file = q.run(
        "metadata",
        sp::strings(&["cargo", "metadata", "--locked", "--format-version", "1"]),
    )?;
    let metadata = sp::read_json(&meta_file)?;
    let packages = at(&entry, "packages")?.as_array().unwrap_or(&[]).to_vec();
    let metadata_packages = at(&metadata, "packages")?
        .as_array()
        .unwrap_or(&[])
        .to_vec();
    let mut wrappers: Vec<Value> = packages
        .iter()
        .filter(|p| matches!(p.at("role").as_str(), Some("wrapper" | "combined")))
        .cloned()
        .collect();
    if wrappers.is_empty() {
        wrappers = packages
            .iter()
            .filter(|p| {
                metadata_packages.iter().any(|m| {
                    m.at("name") == p.at("name")
                        && m.at("targets").as_array().unwrap_or(&[]).iter().any(|t| {
                            t.at("kind")
                                .as_array()
                                .unwrap_or(&[])
                                .iter()
                                .any(|k| k.as_str() == Some("cdylib"))
                        })
                })
            })
            .cloned()
            .collect();
    }
    if wrappers.len() != 1 {
        return Err(runtime(
            "exactly one native plugin export package is required",
        ));
    }
    let package = metadata_packages
        .iter()
        .find(|p| p.at("name") == wrappers[0].at("name"))
        .ok_or_else(|| sp::Error::new(sp::Kind::Runtime, ""))?
        .clone();
    let target = package
        .at("targets")
        .as_array()
        .unwrap_or(&[])
        .iter()
        .find(|t| {
            t.at("kind")
                .as_array()
                .unwrap_or(&[])
                .iter()
                .any(|k| k.as_str() == Some("cdylib"))
        })
        .ok_or_else(|| sp::Error::new(sp::Kind::Runtime, ""))?
        .clone();
    let package_name = sp::at_str(&package, "name")?.to_owned();
    q.run(
        "native-library",
        sp::strings(&[
            "cargo",
            "build",
            "--locked",
            "-p",
            &package_name,
            "--all-features",
            "--lib",
        ]),
    )?;
    let library = PathBuf::from(q.env.get("CARGO_TARGET_DIR").unwrap_or(""))
        .join("debug")
        .join(format!("lib{}{}", sp::at_str(&target, "name")?, suffix()));
    if !library.is_file() {
        return Err(runtime("native library was not produced"));
    }
    q.env.set("BUSBAR_PLUGIN_CDYLIB", sp::text(&library));
    prepare_runtime(q)?;
    let nextest = format!(
        "admission:{}",
        sp::text(&q.trusted.join("ci/native-nextest.toml"))
    );
    q.run(
        "plugin-runtime",
        sp::strings(&[
            "cargo",
            "nextest",
            "run",
            "--locked",
            "--workspace",
            "--all-features",
            "--no-fail-fast",
            "--tool-config-file",
            &nextest,
        ]),
    )?;
    q.run(
        "plugin-doctests",
        sp::strings(&[
            "cargo",
            "test",
            "--locked",
            "--workspace",
            "--all-features",
            "--doc",
            "--no-fail-fast",
        ]),
    )?;
    if q.root.join("deny.toml").is_file() {
        q.run(
            "dependency-policy",
            sp::strings(&["cargo", "deny", "check"]),
        )?;
    }
    if q.root.join("supply-chain/config.toml").is_file() {
        q.run("dependency-vet", sp::strings(&["cargo", "vet"]))?;
    }
    // Preserve repository-owned required extra selections; read the command
    // from the trusted fleet registry, not a candidate-controlled CI script.
    let registry = sp::read_text(&q.trusted.join("plugins.yaml"))?;
    let name = q.repository.rsplit('/').next().unwrap_or("").to_owned();
    if let Some(extra) = registered_extra_test(&registry, &name)?.filter(|e| !e.is_empty()) {
        q.run(
            "plugin-required-extra",
            vec![
                "bash".into(),
                "-euo".into(),
                "pipefail".into(),
                "-c".into(),
                extra,
            ],
        )?;
    }
    q.conformance("plugin-native-conformance")?;
    let collected = q.collect_output(
        &library,
        &q.evidence.join(library.file_name().unwrap_or_default()),
        2 << 30,
        true,
    )?;
    q.receipt
        .set("library_sha256", super::confine::digest(&collected)?.into());
    q.receipt.set(
        "lock_sha256",
        super::confine::digest(&q.root.join("Cargo.lock"))?.into(),
    );
    q.receipt.set("private", entry.at("private").clone());
    Ok(())
}

fn qualify_c(q: &mut Q, _entry: &Value, sdk: &Path) -> R<()> {
    let recipe = product::load_c_recipe(&q.policy, &q.repository, &q.root, None)?;
    let library = q
        .work
        .join("architecture")
        .join(format!("plugin{}", suffix()));
    q.env.set(
        "BUSBAR_C_ABI_SOURCES",
        sp::text(&q.root.join(recipe.at("test-root").as_str().unwrap_or(""))),
    );
    q.env.set("BUSBAR_C_ABI_LIBRARY", sp::text(&library));
    q.run(
        "c-native-loader",
        sp::strings(&[
            "cargo",
            "test",
            "--locked",
            "--manifest-path",
            &sp::text(&sdk.join("Cargo.toml")),
            "-p",
            "busbar-plugin-loader",
            "--test",
            "c_abi",
        ]),
    )?;
    // Owner test locations are data; required instrumentation and stages are fixed.
    let include = sdk.join(
        Path::new(product::PUBLIC_C_HEADER)
            .parent()
            .unwrap_or(Path::new("")),
    );
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .unwrap_or(&[])
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    };
    let mut sources: Vec<String> = Vec::new();
    for relative in strings(recipe.at("unit").at("sources"))
        .iter()
        .chain(strings(recipe.at("sources")).iter())
    {
        sources.push(sp::text(&q.root.join(relative)));
    }
    let mut common = sp::strings(&[
        "cc",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-pthread",
    ]);
    common.extend(
        strings(recipe.at("unit").at("defines"))
            .iter()
            .map(|d| format!("-D{d}")),
    );
    common.push("-I".into());
    common.push(sp::text(&include));
    common.extend(sources);
    for (name, flags) in [
        ("unit", vec![]),
        ("unit-tsan", sp::strings(&["-fsanitize=thread", "-g"])),
    ] {
        let binary = q.work.join(name);
        let mut build = common.clone();
        build.extend(flags);
        build.push("-o".into());
        build.push(sp::text(&binary));
        q.run(&format!("c-build-{name}"), build)?;
        q.env.set("TSAN_OPTIONS", "halt_on_error=1");
        if name == "unit-tsan" && cfg!(target_os = "linux") {
            sanitizer::run_c_unit_tsan(q)?;
        } else {
            q.run(&format!("c-{name}"), vec![sp::text(&binary)])?;
        }
    }
    let schema = q.work.join("settings-schema");
    let mut build = sp::strings(&[
        "cc",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-I",
    ]);
    build.push(sp::text(&include));
    build
        .push(sp::text(&q.root.join(
            recipe.at("schema").at("source").as_str().unwrap_or(""),
        )));
    for relative in strings(recipe.at("sources")) {
        build.push(sp::text(&q.root.join(relative)));
    }
    build.push("-o".into());
    build.push(sp::text(&schema));
    q.run("c-build-schema", build)?;
    let driver = q
        .root
        .join(recipe.at("schema").at("driver").as_str().unwrap_or(""));
    q.run("c-schema", pysteps::c_schema(&driver, &schema))?;
    let destination = q.evidence.join(library.file_name().unwrap_or_default());
    let collected = q.collect_output(&library, &destination, 2 << 30, true)?;
    q.receipt
        .set("library_sha256", super::confine::digest(&collected)?.into());
    q.receipt.set("private", false.into());
    Ok(())
}

/// Prepare owner test subjects outside nextest's per-test runtime deadline.
pub fn prepare_runtime(q: &mut Q) -> R<()> {
    let settings = native_settings(&q.repository, &q.policy)?;
    if let Some(script) = settings.get("prepare_runtime").and_then(Value::as_str) {
        let command = product::regular_under(&q.root.join(script), &q.root)?;
        q.run(
            "plugin-runtime-prepare",
            vec![
                "bash".into(),
                "-euo".into(),
                "pipefail".into(),
                sp::text(&command),
            ],
        )?;
    }
    Ok(())
}

/// Select one already registered readonly tree without changing roots.
fn generated_architecture_context(q: &mut Q, checkout: &Path, label: &str) -> R<(PathBuf, String)> {
    let checkout = sp::resolve(checkout);
    let execution = q.execution();
    if !execution.extra_readonly.contains(&checkout)
        || !checkout.starts_with(execution.roots.candidate.join("generated"))
    {
        return Err(violation(
            "generated architecture checkout is not registered readonly",
        ));
    }
    let (parent, expected) = execution.write_context()?;
    need(
        super::confine::digest(&parent)? == expected,
        "parent execution context changed",
    )?;
    let mut context = sp::read_json(&parent)?;
    context.set(
        "architecture_checkout",
        object([
            ("path", sp::text(&checkout).into()),
            ("source", product::generated_revision(&checkout)?.into()),
        ]),
    );
    let path = execution
        .control
        .join(format!("generated-{label}-execution-context.json"));
    sp::write(&path, json::dumps(&context, true) + "\n")?;
    let digest = super::confine::digest(&path)?;
    Ok((path, digest))
}

fn quoted(text: &str) -> String {
    json::dumps(&Value::from(text), false)
}

/// One generator, with all fourteen kind/distribution combinations checked by
/// the same trusted role graph, source guard and native door fixtures.
pub fn qualify_generator(q: &mut Q) -> R<()> {
    let host = q.host()?;
    let pin = sp::at_str(
        &sp::read_json(&host.join("scripts/ci-product-pins.json"))?,
        "sdk",
    )?
    .to_owned();
    let sdk = q.sdk()?;
    q.env.set("BUSBAR_SDK_CHECKOUT", sp::text(&sdk));
    q.env.set("BUSBAR_SDK_REVISION", pin.as_str());
    q.env.set(
        "BUSBAR_SCAFFOLD_OUTPUT",
        sp::text(&q.work.join("generated")),
    );
    q.receipt
        .set("host_revision", git(&host, &["rev-parse", "HEAD"])?.into());
    q.receipt.set("sdk_revision", pin.into());
    let nextest = format!(
        "admission:{}",
        sp::text(&q.trusted.join("ci/native-nextest.toml"))
    );
    q.run("fmt", sp::strings(&["cargo", "fmt", "--all", "--check"]))?;
    q.run(
        "clippy",
        sp::strings(&[
            "cargo",
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ]),
    )?;
    q.run(
        "tooling-runtime",
        sp::strings(&[
            "cargo",
            "nextest",
            "run",
            "--workspace",
            "--locked",
            "--no-fail-fast",
            "--tool-config-file",
            &nextest,
        ]),
    )?;
    q.run(
        "tooling-doctests",
        sp::strings(&["cargo", "test", "--workspace", "--doc", "--locked"]),
    )?;
    q.run(
        "render-canonical",
        sp::strings(&[
            "cargo",
            "test",
            "--locked",
            "-p",
            "busbar-release-plugin",
            "--test",
            "boundary_scaffold",
            "canonical_seven_kind_skeletons",
            "--",
            "--ignored",
            "--exact",
        ]),
    )?;
    let mut results = Vec::new();
    for (variant, owner) in [("open-source", "GetBusbar"), ("enterprise", "BusbarInc")] {
        for kind in [
            "auth",
            "secret",
            "store",
            "hook",
            "export",
            "plane",
            "transport",
        ] {
            let name = format!("busbar-{kind}-boundary-example");
            let stem = name.strip_prefix("busbar-").unwrap_or(&name).to_owned();
            let root = q.work.join("generated").join(variant).join(&name);
            let repo = format!("{owner}/{name}");
            let label = format!("{variant}-{kind}");
            q.run_in(
                &format!("{label}-fmt"),
                sp::strings(&["cargo", "fmt", "--all"]),
                &root,
            )?;
            q.run_in(
                &format!("{label}-metadata"),
                sp::strings(&["cargo", "metadata", "--format-version", "1"]),
                &root,
            )?;
            q.run_in(
                &format!("{label}-clippy"),
                sp::strings(&[
                    "cargo",
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ]),
                &root,
            )?;
            q.run_in(
                &format!("{label}-build"),
                sp::strings(&[
                    "cargo",
                    "build",
                    "--locked",
                    "-p",
                    &format!("{name}-plugin"),
                    "--lib",
                ]),
                &root,
            )?;
            let library = PathBuf::from(q.env.get("CARGO_TARGET_DIR").unwrap_or(""))
                .join("debug")
                .join(format!("lib{}_plugin{}", name.replace('-', "_"), suffix()));
            q.env.set("BUSBAR_PLUGIN_CDYLIB", sp::text(&library));
            q.run_in(
                &format!("{label}-native-doors"),
                sp::strings(&[
                    "cargo",
                    "test",
                    "--locked",
                    "-p",
                    &format!("{name}-plugin"),
                    "--test",
                    "conformance",
                ]),
                &root,
            )?;
            q.execution().register_generated(&root)?;
            let scratch = q.harness.join(format!("generated-guard-{label}"));
            sp::mkdir(&scratch, 0o777, false)?;
            let policy_file = scratch.join("policy.toml");
            let quoted_repo = quoted(&repo);
            let addition = format!(
                "\n[repositories.{quoted_repo}]\nkind = {}\nprivate = {}\n[[repositories.{quoted_repo}.packages]]\nname = {}\nmanifest = {}\nrole = \"implementation\"\ndev_allows = []\n[[repositories.{quoted_repo}.packages]]\nname = {}\nmanifest = {}\nrole = \"wrapper\"\ndev_allows = [\"busbar-contract\", \"busbar-plugin-loader\"]\n",
                quoted(kind),
                if variant == "enterprise" {
                    "true"
                } else {
                    "false"
                },
                quoted(&name),
                quoted(&format!("{stem}/Cargo.toml")),
                quoted(&format!("{name}-plugin")),
                quoted(&format!("{stem}-plugin/Cargo.toml")),
            );
            let base = sp::read_text(&q.trusted.join("ci/architecture.toml"))?;
            sp::write(&policy_file, base + &addition)?;
            let output = q.evidence.join(format!("{label}-architecture.json"));
            let (context, expected) = generated_architecture_context(q, &root, &label)?;
            let command = pysteps::architecture(
                &q.trusted,
                &policy_file,
                &repo,
                &root,
                &scratch,
                &output,
                None,
                Some((&context, &expected)),
            );
            q.run_controller(&format!("{label}-architecture"), command)?;
            let result = sp::read_json(&output)?;
            let rows = at(&result, "candidate_execution")?
                .as_array()
                .unwrap_or(&[])
                .to_vec();
            q.execution().observations.extend(rows);
            let mut row = object([("kind", kind.into()), ("distribution", variant.into())]);
            for (key, value) in result.as_object().into_iter().flatten() {
                if key == "kind" || key == "distribution" {
                    return Err(sp::Error::new(
                        sp::Kind::Type,
                        format!("dict() got multiple values for keyword argument '{key}'"),
                    ));
                }
                row.set(key, value.clone());
            }
            results.push(row);
        }
    }
    q.receipt.set("generated_plugins", Value::Array(results));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_extra_tests_are_read_exactly() {
        let registry = "fleet:\n  busbar_ref: \"x\"\nplugins:\n  - repo: busbar-store-mysql\n    kind: store\n    macos_test: \"cargo build\"\n  - repo: busbar-store-valkey\n    extra_test: \"cargo test -p busbar-store-valkey --locked -- --ignored --test-threads=1\"\n    former_names: [busbar-store-valkey-plugin]\n  - repo: busbar-transport-ws\n    busbar_checkout: true\n    extra_test: |-\n      set -euo pipefail\n      bash testing/ws-conformance/scripts/run.sh --subject\n    # comment\n  - repo: busbar-secret-c\n    extra_test: \"set -euo pipefail; trap 'rm -rf \\\"$work\\\"' EXIT\"\nexcluded_repos:\n  - x\n";
        assert_eq!(
            registered_extra_test(registry, "busbar-store-mysql").unwrap(),
            None
        );
        assert_eq!(
            registered_extra_test(registry, "busbar-store-valkey")
                .unwrap()
                .as_deref(),
            Some("cargo test -p busbar-store-valkey --locked -- --ignored --test-threads=1")
        );
        assert_eq!(
            registered_extra_test(registry, "busbar-transport-ws")
                .unwrap()
                .as_deref(),
            Some("set -euo pipefail\nbash testing/ws-conformance/scripts/run.sh --subject")
        );
        assert_eq!(
            registered_extra_test(registry, "busbar-secret-c")
                .unwrap()
                .as_deref(),
            Some("set -euo pipefail; trap 'rm -rf \"$work\"' EXIT")
        );
        assert_eq!(registered_extra_test(registry, "x").unwrap(), None);
    }
    #[test]
    fn the_trusted_fleet_registry_reads_like_yaml_safe_load() {
        // Ground truth from yaml.safe_load(plugins.yaml) at this revision.
        let registry = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins.yaml"),
        )
        .unwrap();
        let expected: &[(&str, Option<&str>)] = &[
            (
                "busbar-store-valkey",
                Some("cargo test -p busbar-store-valkey --locked -- --ignored --test-threads=1"),
            ),
            (
                "busbar-transport-ws",
                Some("set -euo pipefail\nbash testing/ws-conformance/scripts/run.sh --subject"),
            ),
            (
                "busbar-secret-c",
                Some(
                    "set -euo pipefail; work=$(mktemp -d); trap 'rm -rf \"$work\"' EXIT; inc=\"$BUSBAR_CHECKOUT/crates/busbar-contract/include\"; cc -std=c11 -Wall -Wextra -Werror -pedantic -pthread -DBUSBAR_SECRET_C_UNIT -I \"$inc\" secret-c/tests/unit.c secret-c/busbar_secret_c.c -o \"$work/unit\"; \"$work/unit\"; cc -std=c11 -Wall -Wextra -Werror -pedantic -pthread -DBUSBAR_SECRET_C_UNIT -fsanitize=thread -g -I \"$inc\" secret-c/tests/unit.c secret-c/busbar_secret_c.c -o \"$work/unit-tsan\"; TSAN_OPTIONS=halt_on_error=1 \"$work/unit-tsan\"",
                ),
            ),
        ];
        let repos: Vec<&str> = registry
            .lines()
            .filter_map(|l| l.strip_prefix("  - repo: "))
            .collect();
        assert_eq!(repos.len(), 35);
        for repo in repos {
            let wanted = expected
                .iter()
                .find(|(r, _)| *r == repo)
                .and_then(|(_, v)| *v);
            assert_eq!(
                registered_extra_test(&registry, repo).unwrap().as_deref(),
                wanted,
                "{repo}"
            );
        }
    }
}
