//! Controller intake of pre-recorded, independently pinned legacy fixtures
//! (former `native_staged_fixtures`).
use super::sp::{self, R, Spec, need, value_error};
use super::{Q, fetch_environment, git, native_settings, server_url};
use crate::json::{self, Value, object};
use crate::sha256;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// `str.splitlines()`.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (at, c) = chars[i];
        if matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            lines.push(&text[start..at]);
            let mut next = at + c.len_utf8();
            if c == '\r' && chars.get(i + 1).is_some_and(|(_, n)| *n == '\n') {
                next += 1;
                i += 1;
            }
            start = next;
        }
        i += 1;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `regular(path, limit)`: a bounded single-link regular file, unchanged while read.
pub fn regular(path: &Path, limit: u64) -> R<Vec<u8>> {
    need(
        !sp::self_and_parents(path).iter().any(|p| sp::is_symlink(p)),
        "indirect staged fixture file",
    )?;
    use std::os::fd::FromRawFd;
    let fd = sp::openat(
        sp::AT_FDCWD,
        path.as_os_str(),
        sp::flags::O_NOFOLLOW | sp::O_NONBLOCK,
    )?;
    let mut stream = unsafe { std::fs::File::from_raw_fd(fd) };
    let before = stream.metadata().map_err(|e| sp::os_error(&e, None))?;
    need(
        before.file_type().is_file() && before.nlink() == 1 && before.len() <= limit,
        "staged fixture file is not a bounded regular file",
    )?;
    let mut payload = Vec::new();
    (&mut stream)
        .take(limit + 1)
        .read_to_end(&mut payload)
        .map_err(|e| sp::os_error(&e, None))?;
    let after = stream.metadata().map_err(|e| sp::os_error(&e, None))?;
    need(
        payload.len() as u64 == before.len()
            && payload.len() as u64 <= limit
            && (
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) == (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ),
        "staged fixture changed during intake",
    )?;
    Ok(payload)
}

fn hex(text: &str, n: usize) -> bool {
    text.len() == n
        && text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn unpack2(fields: Vec<&str>) -> R<(&str, &str)> {
    match fields.as_slice() {
        [a, b] => Ok((a, b)),
        [_] | [] => Err(value_error(format!(
            "not enough values to unpack (expected 2, got {})",
            fields.len()
        ))),
        _ => Err(value_error("too many values to unpack (expected 2)")),
    }
}

fn unpack3(fields: Vec<&str>) -> R<(&str, &str, &str)> {
    match fields.as_slice() {
        [a, b, c] => Ok((a, b, c)),
        _ if fields.len() < 3 => Err(value_error(format!(
            "not enough values to unpack (expected 3, got {})",
            fields.len()
        ))),
        _ => Err(value_error("too many values to unpack (expected 3)")),
    }
}

fn table(path: &Path) -> R<Vec<Vec<String>>> {
    Ok(splitlines(&sp::read_text(path)?)
        .into_iter()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect())
}

/// `validate_manifest(files, trusted)`: the fixed published SQLite recording.
fn validate_manifest(files: &[(String, Vec<u8>)], trusted: &Path) -> R<Value> {
    let get = |name: &str| files.iter().find(|(n, _)| n == name).map(|(_, c)| c);
    let manifest = String::from_utf8(get("MANIFEST.tsv").cloned().unwrap_or_default())
        .map_err(|_| value_error("'utf-8' codec can't decode MANIFEST.tsv"))?;
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut listed: Vec<(String, String)> = Vec::new();
    for line in splitlines(&manifest) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = unpack2(line.splitn(2, '\t').collect())?;
        if key == "file" {
            let (name, digest) = unpack2(value.split_whitespace().collect())?;
            need(
                !listed.iter().any(|(n, _)| n == name) && get(name).is_some(),
                "duplicate or missing migration file",
            )?;
            listed.push((name.to_owned(), digest.to_owned()));
        } else {
            need(
                ["busbar", "plugin", "backend", "recorder", "requests"].contains(&key)
                    && !rows.iter().any(|(k, _)| k == key),
                "invalid migration manifest field",
            )?;
            rows.push((key.to_owned(), value.to_owned()));
        }
    }
    let row = |key: &str| {
        rows.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    need(
        rows.len() == 5
            && row("backend") == "sqlite"
            && hex(row("recorder"), 40)
            && row("requests").split_whitespace().collect::<Vec<_>>()
                == ["200", "200", "200", "503", "200", "200"],
        "migration fixture is not the fixed published SQLite recording",
    )?;
    let mut listed_names: Vec<&str> = listed.iter().map(|(n, _)| n.as_str()).collect();
    listed_names.sort();
    let mut others: Vec<&str> = files
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| *n != "MANIFEST.tsv")
        .collect();
    others.sort();
    need(
        listed_names == others
            && listed_names.contains(&"governance.db")
            && listed_names.contains(&"rows.json"),
        "migration manifest does not cover its complete fixture",
    )?;
    for (name, expected) in &listed {
        need(
            sha256::hex(get(name).unwrap()) == *expected,
            "migration manifest file digest differs",
        )?;
    }
    let (version, binary, digest) = unpack3(row("busbar").split_whitespace().collect())?;
    need(
        version == "v1.5.5",
        "migration fixture did not use published 1.5.5",
    )?;
    let golden = table(&trusted.join("testing/shadow-oracle/golden-digests.tsv"))?;
    need(
        golden.iter().any(|r| {
            r.first().map(String::as_str) == Some("1.5.5")
                && r.get(1).map(String::as_str) == Some(binary)
                && r.last().map(String::as_str) == Some(digest)
        }),
        "migration writer is not a protected published binary",
    )?;
    let (tag, artifact, digest) = unpack3(row("plugin").split_whitespace().collect())?;
    let plugins = table(&trusted.join("testing/shadow-oracle/plugin-digests.tsv"))?;
    need(
        plugins
            .iter()
            .any(|r| r.len() >= 4 && r[..4] == ["store-sqlite", tag, artifact, digest]),
        "migration plugin is not a protected published SQLite asset",
    )?;
    Ok(Value::Object(
        rows.into_iter().map(|(k, v)| (k, Value::from(v))).collect(),
    ))
}

fn sqlite_origin(origin: &Value) -> bool {
    origin.has_keys(&["repository", "revision", "path"])
        && origin.at("repository").as_str() == Some("GetBusbar/busbar-store-sqlite")
        && origin.at("revision").as_str().is_some_and(|r| hex(r, 40))
        && origin.at("path").as_str() == Some("store-sqlite/tests/fixtures/1.5.5")
}

/// `stage(q, path, expected)`.
pub fn stage(q: &mut Q, path: &Path, expected: &str) -> R<Vec<(String, PathBuf)>> {
    let payload = regular(path, 4 << 20)?;
    need(
        sha256::hex(&payload) == expected,
        "protected fixture input plan digest differs",
    )?;
    let data = sp::loads(&payload)?;
    need(
        data.has_keys(&["schema", "fixtures"])
            && data.at("schema").as_str() == Some("busbar.native-staged-fixtures/1")
            && data
                .at("fixtures")
                .keys()
                .iter()
                .all(|k| *k == "sqlite-1.5.5"),
        "unknown staged fixture plan",
    )?;
    let mut staged = Vec::new();
    let mut evidence: Vec<(String, Value)> = Vec::new();
    let root = sp::resolve(&q.root);
    let work = sp::resolve(&q.work);
    for (name, entry) in data.at("fixtures").as_object().into_iter().flatten() {
        need(
            entry.has_keys(&["path", "files", "origin"])
                && entry.at("files").is_object()
                && sqlite_origin(entry.at("origin")),
            "invalid staged SQLite fixture identity",
        )?;
        let source = PathBuf::from(sp::at_str(entry, "path")?);
        need(
            source.is_absolute()
                && source == sp::resolve(&source)
                && source.is_dir()
                && !source.starts_with(&root)
                && !source.starts_with(&work),
            "staged fixture source is candidate writable",
        )?;
        let listed = entry.at("files");
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let mut total = 0usize;
        let mut items = sp::rglob(&source);
        sp::sort_paths(&mut items);
        for item in items {
            need(!sp::is_symlink(&item), "indirect staged fixture input")?;
            if item.is_dir() {
                continue;
            }
            let relative = sp::text(item.strip_prefix(&source).unwrap_or(&item));
            need(
                listed.get(&relative).is_some(),
                "unlisted staged fixture file",
            )?;
            let content = regular(&item, 64 << 20)?;
            total += content.len();
            need(total <= 128 << 20, "staged fixture exceeds byte budget")?;
            need(
                listed.at(&relative).as_str() == Some(sha256::hex(&content).as_str()),
                "staged fixture file digest differs",
            )?;
            files.push((relative, content));
        }
        let mut names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        names.sort();
        let mut wanted = listed.keys();
        wanted.sort();
        need(
            names == wanted && names.contains(&"MANIFEST.tsv"),
            "staged fixture file set differs",
        )?;
        let recorded = validate_manifest(&files, &q.trusted)?;
        let destination = q.control.join(format!("staged-{name}"));
        sp::mkdir(&destination, 0o755, false)?;
        let written = (|| -> R<()> {
            for (relative, content) in &files {
                let target = destination.join(relative);
                if let Some(parent) = target.parent() {
                    sp::mkdirs(parent, true)?;
                }
                sp::write(&target, content)?;
                sp::chmod(&target, 0o444)?;
            }
            q.execution().extra_readonly.push(destination.clone());
            Ok(())
        })();
        if let Err(error) = written {
            let _ = sp::rmtree(&destination);
            return Err(error);
        }
        staged.push((name.clone(), destination));
        evidence.push((
            name.clone(),
            object([
                ("origin", entry.at("origin").clone()),
                ("files", entry.at("files").clone()),
                ("recorded", recorded),
            ]),
        ));
    }
    q.receipt.set(
        "staged_fixture_inputs",
        object([
            ("plan_sha256", expected.into()),
            ("fixtures", Value::Object(evidence)),
        ]),
    );
    Ok(staged)
}

/// `collect_required(q)`: resolve the policy-owned historical fixture.
pub fn collect_required(q: &mut Q) -> R<()> {
    let settings = native_settings(&q.repository, &q.policy)?;
    let Some(name) = settings
        .get("migration_fixture")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return Ok(());
    };
    if q.staged_fixtures.iter().any(|(n, _)| *n == name) {
        return Ok(());
    }
    let payload = regular(&q.trusted.join("ci/native-fixtures.json"), 4 << 20)?;
    let catalog = sp::loads(&payload)?;
    need(
        catalog.has_keys(&["schema", "fixtures"])
            && catalog.at("schema").as_str() == Some("busbar.native-fixture-catalog/1")
            && catalog.at("fixtures").get(&name).is_some(),
        "required migration fixture is absent from protected catalog",
    )?;
    let entry = catalog.at("fixtures").at(&name).clone();
    need(
        entry.has_keys(&["origin", "files"]) && entry.at("files").is_object(),
        "invalid fixture catalog entry",
    )?;
    let origin = entry.at("origin");
    need(sqlite_origin(origin), "unapproved migration source")?;
    let revision = origin.at("revision").as_str().unwrap_or("").to_owned();
    let directory = q.control.join("migration-source");
    sp::mkdir(&directory, 0o700, false)?;
    let objects = directory.join("objects.git");
    sp::check_call(Spec::new(sp::strings(&[
        "git",
        "init",
        "--bare",
        "--quiet",
        &sp::text(&objects),
    ])))?;
    let environment = fetch_environment()?.pairs();
    let remote = format!(
        "{}/{}.git",
        server_url()?,
        origin.at("repository").as_str().unwrap_or("")
    );
    sp::check_call(
        Spec::new(sp::strings(&[
            "git",
            "-C",
            &sp::text(&objects),
            "fetch",
            "--quiet",
            "--depth",
            "1",
            &remote,
            &format!("{revision}:refs/heads/fixture"),
        ]))
        .env(&environment)
        .timeout(300),
    )?;
    need(
        git(&objects, &["rev-parse", "refs/heads/fixture"])? == revision,
        "migration source revision differs",
    )?;
    let source = directory.join("files");
    sp::mkdir(&source, 0o777, false)?;
    let base = origin.at("path").as_str().unwrap_or("").to_owned();
    for (relative, expected) in entry.at("files").as_object().into_iter().flatten() {
        need(
            !relative.is_empty()
                && relative
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_./-".contains(&c))
                && !relative.starts_with('/')
                && relative.split('/').all(|p| !matches!(p, "" | "." | "..")),
            "invalid migration source file",
        )?;
        let value = sp::check_output(
            Spec::new(sp::strings(&[
                "git",
                "-C",
                &sp::text(&objects),
                "show",
                &format!("{revision}:{base}/{relative}"),
            ]))
            .timeout(30),
        )?;
        need(
            value.len() <= 64 << 20 && Some(sha256::hex(&value).as_str()) == expected.as_str(),
            "historical migration source digest differs",
        )?;
        let target = source.join(relative);
        if let Some(parent) = target.parent() {
            sp::mkdirs(parent, true)?;
        }
        sp::write(&target, value)?;
    }
    let mut fixture = entry.clone();
    fixture.set("path", sp::text(&source).into());
    let plan = object([
        ("schema", "busbar.native-staged-fixtures/1".into()),
        ("fixtures", Value::Object(vec![(name.clone(), fixture)])),
    ]);
    let path = directory.join("plan.json");
    sp::write(&path, json::dumps(&plan, true) + "\n")?;
    let digest = sha256::hex(&sp::read(&path)?);
    let staged = stage(q, &path, &digest)?;
    for (name, destination) in staged {
        q.staged_fixtures.retain(|(n, _)| *n != name);
        q.staged_fixtures.push((name, destination));
    }
    if let Some(record) = q.receipt.get_mut("staged_fixture_inputs") {
        record.set("catalog_sha256", sha256::hex(&payload).into());
    }
    sp::rmtree(&objects)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(
            splitlines("a\r\nb\rc\nd\x0be"),
            vec!["a", "b", "c", "d", "e"]
        );
        assert_eq!(splitlines("a\n\nb\n"), vec!["a", "", "b"]);
        assert!(splitlines("").is_empty());
    }

    #[test]
    fn regular_intake_refuses_links_and_oversize() {
        let base =
            sp::resolve(&std::env::temp_dir()).join(format!("busbar-ci-staged-{}", sp::uuid_hex()));
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("f");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(regular(&file, 3).unwrap(), b"abc");
        assert_eq!(
            regular(&file, 2).unwrap_err().message,
            "staged fixture file is not a bounded regular file"
        );
        std::os::unix::fs::symlink(&file, base.join("l")).unwrap();
        assert_eq!(
            regular(&base.join("l"), 9).unwrap_err().message,
            "indirect staged fixture file"
        );
        std::fs::hard_link(&file, base.join("h")).unwrap();
        assert_eq!(
            regular(&file, 9).unwrap_err().message,
            "staged fixture file is not a bounded regular file"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
