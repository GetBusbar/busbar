//! Protected, measured public instruments mounted read-only for one native job
//! (former `native_conformance_inputs.stage` and `native_python_runtime.bind`).
use super::Q;
use super::sp::{self, R, need};
use super::staged::regular;
use crate::confine::sha_canonical;
use crate::json::{self, Value, object};
use crate::sha256;
use std::path::{Path, PathBuf};

fn hex(text: &str, n: usize) -> bool {
    text.len() == n
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

struct Split<'a> {
    scheme: String,
    netloc: &'a str,
    path: &'a str,
    query: &'a str,
    fragment: &'a str,
}

/// `urllib.parse.urlsplit` for absolute `scheme://netloc/path?query#fragment`.
fn urlsplit(url: &str) -> Split<'_> {
    let (scheme, rest) = match url.split_once(':') {
        Some((scheme, rest))
            if scheme
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) =>
        {
            (scheme.to_ascii_lowercase(), rest)
        }
        _ => (String::new(), url),
    };
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (netloc, path) = match rest.strip_prefix("//") {
        Some(after) => match after.find('/') {
            Some(i) => (&after[..i], &after[i..]),
            None => (after, ""),
        },
        None => ("", rest),
    };
    Split {
        scheme,
        netloc,
        path,
        query,
        fragment,
    }
}

fn provenance_ok(origin: &Value) -> bool {
    if !origin.has_keys(&["uri", "sha256"]) {
        return false;
    }
    let uri = origin.at("uri").as_str().unwrap_or("");
    let url = urlsplit(uri);
    let archive = url
        .path
        .strip_prefix("/api/v4/projects/")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(project, tail)| !project.is_empty() && tail == "repository/archive.tar.gz");
    let immutable = url.netloc == "github.com"
        && archive
        && url
            .query
            .strip_prefix("sha=")
            .is_some_and(|sha| hex(sha, 40));
    let credentials = url.netloc.contains('@');
    url.scheme == "https"
        && !url.netloc.is_empty()
        && !credentials
        && (url.query.is_empty() || immutable)
        && url.fragment.is_empty()
        && origin.at("sha256").as_str().is_some_and(|s| hex(s, 64))
}

/// `stage(q, manifest, expected)`.
pub fn stage(q: &mut Q, manifest: &Path, expected: &str) -> R<()> {
    let payload = regular(manifest, 16 << 20)?;
    need(
        sha256::hex(&payload) == expected,
        "conformance input plan digest differs",
    )?;
    let data = sp::loads(&payload)?;
    need(
        data.has_keys(&["schema", "bundles"])
            && data.at("schema").as_str() == Some("busbar.native-conformance-inputs/1")
            && data
                .at("bundles")
                .as_object()
                .is_some_and(|b| b.len() <= 32),
        "invalid conformance input plan",
    )?;
    let root = sp::resolve(&q.root);
    let work = sp::resolve(&q.work);
    let mut mounted: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut inventory: Vec<(String, Value)> = Vec::new();
    let mut total = 0usize;
    for (name, bundle) in data.at("bundles").as_object().into_iter().flatten() {
        let mut chars = name.chars();
        let name_ok = name.chars().count() <= 64
            && chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        need(
            name_ok
                && bundle.has_keys(&["path", "files", "provenance"])
                && bundle
                    .at("files")
                    .as_object()
                    .is_some_and(|f| !f.is_empty() && f.len() <= 100_000)
                && bundle
                    .at("provenance")
                    .as_array()
                    .is_some_and(|p| !p.is_empty()),
            "invalid conformance tool bundle",
        )?;
        for origin in bundle.at("provenance").as_array().unwrap_or(&[]) {
            need(
                origin.is_object() && origin.has_keys(&["uri", "sha256"]),
                "invalid instrument provenance",
            )?;
            need(
                provenance_ok(origin),
                "instrument provenance must be a credential-free pinned HTTPS source",
            )?;
        }
        let mut source = PathBuf::from(sp::at_str(bundle, "path")?);
        if !source.is_absolute() {
            need(
                source.components().next().is_some()
                    && source
                        .components()
                        .all(|c| !matches!(c.as_os_str().to_str(), Some("." | ".."))),
                "portable conformance bundle escapes its package",
            )?;
            source = sp::resolve(manifest)
                .parent()
                .unwrap_or(Path::new("/"))
                .join(source);
        }
        need(
            source.is_absolute()
                && source.is_dir()
                && source == sp::resolve(&source)
                && !source.starts_with(&root)
                && !source.starts_with(&work),
            "conformance bundle is candidate writable",
        )?;
        let destination = q.control.join(format!("conformance-tools-{name}"));
        sp::mkdir(&destination, 0o755, false)?;
        let files = bundle.at("files");
        let copied = (|| -> R<()> {
            let mut actual: Vec<String> = Vec::new();
            for path in sp::rglob(&source) {
                need(!sp::is_symlink(&path), "indirect conformance bundle input")?;
                if path.is_dir() {
                    continue;
                }
                let relative = sp::text(path.strip_prefix(&source).unwrap_or(&path));
                need(
                    files.get(&relative).is_some(),
                    "unlisted conformance instrument",
                )?;
                let spec = files.at(&relative);
                need(
                    spec.has_keys(&["sha256", "executable"])
                        && spec.at("sha256").as_str().is_some_and(|s| hex(s, 64))
                        && spec.at("executable").as_bool().is_some(),
                    "invalid instrument file identity",
                )?;
                let content = regular(&path, 512 << 20)?;
                total += content.len();
                need(
                    total <= 4 << 30,
                    "conformance instruments exceed byte budget",
                )?;
                need(
                    spec.at("sha256").as_str() == Some(sha256::hex(&content).as_str()),
                    "conformance instrument digest differs",
                )?;
                let output = destination.join(&relative);
                if let Some(parent) = output.parent() {
                    sp::mkdirs(parent, true)?;
                }
                sp::write(&output, &content)?;
                sp::chmod(
                    &output,
                    if spec.at("executable").as_bool() == Some(true) {
                        0o555
                    } else {
                        0o444
                    },
                )?;
                actual.push(relative);
            }
            actual.sort();
            actual.dedup();
            let mut wanted = files.keys();
            wanted.sort();
            need(actual == wanted, "conformance instrument file set differs")
        })();
        if let Err(error) = copied {
            let _ = sp::rmtree(&destination);
            return Err(error);
        }
        let target = format!("/opt/busbar-conformance/{name}");
        mounted.push((destination, PathBuf::from(&target)));
        inventory.push((
            name.clone(),
            object([
                ("path", target.as_str().into()),
                ("files", files.clone()),
                ("provenance", bundle.at("provenance").clone()),
            ]),
        ));
    }
    let published = q.control.join("conformance-inputs.json");
    let inventory = Value::Object(inventory);
    let document = object([
        ("schema", data.at("schema").clone()),
        ("bundles", inventory.clone()),
    ]);
    sp::write(&published, json::dumps(&document, true) + "\n")?;
    sp::chmod(&published, 0o444)?;
    let manifest_sha = sha256::hex(&sp::read(&published)?);
    let execution = q.execution();
    execution.conformance_mounts.extend(mounted);
    execution.conformance_mounts.push((
        published.clone(),
        PathBuf::from("/__busbar_conformance_inputs.json"),
    ));
    execution.conformance_inputs_manifest = Some(published);
    q.receipt.set(
        "conformance_inputs",
        object([
            ("plan_sha256", expected.into()),
            ("mounted_manifest_sha256", manifest_sha.into()),
            ("bundles", inventory),
        ]),
    );
    bind(q)
}

pub const PYTHON_RUNTIME: &str = "/opt/busbar-conformance/python-runtime";

/// `native_python_runtime.bind(q)`: an approved offline environment bound
/// to the exact selected image ABI.
pub fn bind(q: &mut Q) -> R<()> {
    let Some(bundle) = q
        .receipt
        .at("conformance_inputs")
        .at("bundles")
        .get("python-runtime")
        .cloned()
    else {
        return Ok(());
    };
    let root = q.control.join("conformance-tools-python-runtime");
    let identity = sp::loads(&regular(&root.join("identity.json"), 65536)?)?;
    let version_ok = identity.at("python_version").as_str().is_some_and(|v| {
        let parts: Vec<&str> = v.split('.').collect();
        parts.len() == 3
            && parts[0] == "3"
            && parts[1..]
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()))
    });
    need(
        identity.has_keys(&[
            "schema",
            "platform",
            "python_version",
            "base_python",
            "image_manifest_sha256",
            "image_config_sha256",
            "executable_sha256",
        ]) && identity.at("schema").as_str() == Some("busbar.native-python-runtime/1")
            && identity.at("platform").as_str() == Some("linux/amd64")
            && version_ok
            && identity.at("base_python").as_str() == Some(super::pysteps::BASE_INTERPRETER)
            && [
                "image_manifest_sha256",
                "image_config_sha256",
                "executable_sha256",
            ]
            .iter()
            .all(|k| identity.at(k).as_str().is_some_and(|v| hex(v, 64))),
        "invalid declared Python runtime ABI",
    )?;
    let executable_ok = bundle
        .at("files")
        .at("bin/python3")
        .at("executable")
        .as_bool()
        == Some(true)
        && identity.at("executable_sha256").as_str()
            == Some(sha256::hex(&regular(&root.join("bin/python3"), 32 << 20)?).as_str());
    need(executable_ok, "Python runtime executable identity differs")?;
    let expected = format!(
        "home = /usr/bin\ninclude-system-site-packages = false\nversion = {}\n",
        identity.at("python_version").as_str().unwrap_or("")
    );
    need(
        regular(&root.join("pyvenv.cfg"), 4096)? == expected.as_bytes(),
        "Python runtime must be a closed standard virtual environment",
    )?;
    let execution = q.execution();
    let image = execution.image().to_owned();
    let pinned = image.rsplit("sha256:").next().unwrap_or("");
    need(
        (identity.at("image_manifest_sha256").as_str() == Some(pinned)
            || identity.at("image_config_sha256").as_str() == Some(pinned))
            && Some(execution.python()) == identity.at("base_python").as_str(),
        "Python runtime does not match the selected image ABI",
    )?;
    let prefix = format!("{PYTHON_RUNTIME}/bin");
    let original = execution
        .config
        .at("environment")
        .at("PATH")
        .as_str()
        .unwrap_or("")
        .to_owned();
    need(
        !original.split(':').any(|p| p == prefix),
        "Python runtime was already registered",
    )?;
    if let Some(environment) = execution.config.get_mut("environment") {
        environment.set("PATH", format!("{prefix}:{original}").into());
    }
    let configuration = sha_canonical(&execution.config);
    if let Some(inputs) = q.receipt.get_mut("conformance_inputs") {
        inputs.set(
            "python_runtime",
            object([
                ("identity", identity),
                ("path", PYTHON_RUNTIME.into()),
                ("executable", format!("{prefix}/python3").into()),
                ("configuration_sha256", configuration.into()),
            ]),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_is_credential_free_and_pinned() {
        let ok = |uri: &str| {
            provenance_ok(&object([
                ("uri", uri.into()),
                ("sha256", "a".repeat(64).into()),
            ]))
        };
        assert!(ok(
            "https://github.com/x/y/releases/download/v1/tool.tar.gz"
        ));
        assert!(ok(&format!(
            "https://github.com/api/v4/projects/7/repository/archive.tar.gz?sha={}",
            "b".repeat(40)
        )));
        assert!(!ok(
            "https://github.com/api/v4/projects/7/repository/archive.tar.gz?sha=main"
        ));
        assert!(!ok("https://user:pass@example.com/x"));
        assert!(!ok("http://example.com/x"));
        assert!(!ok("https://example.com/x#frag"));
        assert!(!ok("https://example.com/x?q=1"));
    }
}
