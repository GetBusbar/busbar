//! `pathlib`/`shutil`/`subprocess` semantics the architecture controller needs:
//! non-strict `resolve`, lexical joins, glob/rglob without following
//! directory links, `copy2`/`copytree` timestamps, OSError and
//! CalledProcessError text, and text-mode subprocess output.
use crate::proc::Result;
use crate::py;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

/// `str(Path(value))` normalization: no `.` components, no duplicate or
/// trailing separators (`..` is kept, as pathlib keeps it).
pub fn norm(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// `base / relative` with pathlib normalization.
pub fn join(base: &Path, relative: impl AsRef<Path>) -> PathBuf {
    norm(&base.join(relative))
}

pub fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `Path(value).resolve()` (non-strict realpath): resolve existing links,
/// keep missing trailing components, normalize `.` and `..`.
pub fn resolve(path: &Path) -> PathBuf {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let mut resolved = PathBuf::from("/");
    let mut missing = false;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                if !missing {
                    match fs::canonicalize(&resolved) {
                        Ok(real) => resolved = real,
                        Err(_) => {
                            // A dangling link still resolves to its target text.
                            if let Ok(target) = fs::read_link(&resolved) {
                                resolved.pop();
                                resolved = resolve(&resolved.join(target));
                            }
                            missing = true;
                        }
                    }
                }
            }
        }
    }
    resolved
}

pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Python `OSError.__str__` for a failed file operation.
pub fn os_error(error: &std::io::Error, path: Option<&Path>) -> String {
    let text = error.to_string();
    let message = match text.rfind(" (os error ") {
        Some(index) => text[..index].to_owned(),
        None => text,
    };
    match (error.raw_os_error(), path) {
        (Some(code), Some(path)) => {
            format!("[Errno {code}] {message}: {}", py::repr_str(&text_of(path)))
        }
        (Some(code), None) => format!("[Errno {code}] {message}"),
        _ => message,
    }
}

fn text_of(path: &Path) -> String {
    text(path)
}

pub fn io<T>(value: std::io::Result<T>, path: &Path) -> Result<T> {
    value.map_err(|e| os_error(&e, Some(path)))
}

pub fn read(path: &Path) -> Result<Vec<u8>> {
    io(fs::read(path), path)
}

/// `Path.read_text()`: strict UTF-8 (UnicodeDecodeError text on failure).
pub fn read_text(path: &Path) -> Result<String> {
    decode(&read(path)?)
}

pub fn decode(data: &[u8]) -> Result<String> {
    match std::str::from_utf8(data) {
        Ok(text) => Ok(text.to_owned()),
        Err(_) => py::decode_utf8(data, false)
            .map(|chars| chars.into_iter().collect())
            .map_err(|e| e.message),
    }
}

/// `Path.read_text(errors='replace')`.
pub fn read_lossy(path: &Path) -> Result<String> {
    Ok(String::from_utf8_lossy(&read(path)?).into_owned())
}

pub fn write(path: &Path, data: impl AsRef<[u8]>) -> Result<()> {
    io(fs::write(path, data), path)
}

pub fn mkdir(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    io(fs::DirBuilder::new().mode(mode).create(path), path)
}

/// `mkdir(parents=True, exist_ok=True)`.
pub fn mkdirs(path: &Path) -> Result<()> {
    io(fs::create_dir_all(path), path)
}

pub fn rmtree(path: &Path) -> Result<()> {
    io(fs::remove_dir_all(path), path)
}

/// `shutil.copyfile(source, destination, follow_symlinks=False)`.
pub fn copyfile(source: &Path, destination: &Path) -> Result<()> {
    let data = read(source)?;
    write(destination, data)
}

fn copystat(source: &Path, destination: &Path) -> Result<()> {
    let metadata = io(fs::symlink_metadata(source), source)?;
    let times = fs::FileTimes::new()
        .set_accessed(io(metadata.accessed(), source)?)
        .set_modified(io(metadata.modified(), source)?);
    let mode = metadata.permissions().mode() & 0o7777;
    io(
        fs::set_permissions(destination, fs::Permissions::from_mode(mode)),
        destination,
    )?;
    let file = io(fs::File::open(destination), destination)?;
    io(file.set_times(times), destination)
}

/// `shutil.copy2(source, destination, follow_symlinks=False)` for a regular file.
pub fn copy2(source: &Path, destination: &Path) -> Result<()> {
    copyfile(source, destination)?;
    copystat(source, destination)
}

/// `shutil.copytree(source, destination, symlinks=True)`.
pub fn copytree(source: &Path, destination: &Path) -> Result<()> {
    mkdirs(destination)?;
    let mut entries: Vec<_> = io(fs::read_dir(source), source)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let target = destination.join(entry.file_name());
        let kind = io(fs::symlink_metadata(&path), &path)?.file_type();
        if kind.is_symlink() {
            let link = io(fs::read_link(&path), &path)?;
            io(std::os::unix::fs::symlink(link, &target), &target)?;
        } else if kind.is_dir() {
            copytree(&path, &target)?;
        } else {
            copy2(&path, &target)?;
        }
    }
    copystat(source, destination)
}

/// `fnmatch.fnmatchcase` for one path segment (`*`, `?`, `[...]`).
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    fn class(p: &[char], c: char) -> Option<(bool, usize)> {
        // Returns (matched, length of class including brackets).
        let mut i = 1;
        let negate = p.get(i).is_some_and(|c| *c == '!');
        if negate {
            i += 1;
        }
        let start = i;
        let mut matched = false;
        while i < p.len() && (p[i] != ']' || i == start) {
            if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
                if p[i] <= c && c <= p[i + 2] {
                    matched = true;
                }
                i += 3;
            } else {
                if p[i] == c {
                    matched = true;
                }
                i += 1;
            }
        }
        if i >= p.len() {
            return None;
        }
        Some((matched != negate, i + 1))
    }
    fn go(n: &[char], p: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|k| go(&n[k..], &p[1..])),
            Some('?') => !n.is_empty() && go(&n[1..], &p[1..]),
            Some('[') => match (n.first(), class(p, n.first().copied().unwrap_or('\0'))) {
                (Some(_), Some((true, len))) => go(&n[1..], &p[len..]),
                (Some(_), Some((false, _))) | (None, Some(_)) => false,
                (_, None) => n.first() == Some(&'[') && go(&n[1..], &p[1..]),
            },
            Some(c) => n.first() == Some(c) && go(&n[1..], &p[1..]),
        }
    }
    let n: Vec<char> = name.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    go(&n, &p)
}

fn wildcard(segment: &str) -> bool {
    segment.contains(['*', '?', '['])
}

fn children(directory: &Path) -> Vec<PathBuf> {
    let mut rows: Vec<PathBuf> = fs::read_dir(directory)
        .map(|it| it.filter_map(|e| e.ok()).map(|e| e.path()).collect())
        .unwrap_or_default();
    rows.sort();
    rows
}

/// Directories below `root` (inclusive), never entering directory links.
fn directories(root: &Path) -> Vec<PathBuf> {
    let mut out = vec![root.to_path_buf()];
    let mut index = 0;
    while index < out.len() {
        let current = out[index].clone();
        index += 1;
        for child in children(&current) {
            if fs::symlink_metadata(&child).is_ok_and(|m| m.is_dir()) {
                out.push(child);
            }
        }
    }
    out
}

/// `Path.glob(pattern)` for `/`-separated segments (`**` recursive).
pub fn glob(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut current = vec![root.to_path_buf()];
    let segments: Vec<&str> = pattern
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        let mut next = Vec::new();
        for base in &current {
            if *segment == "**" {
                next.extend(directories(base));
            } else if wildcard(segment) {
                for child in children(base) {
                    let name = child.file_name().map(|n| n.to_string_lossy().into_owned());
                    if name.is_some_and(|n| fnmatch(&n, segment)) && (last || child.is_dir()) {
                        next.push(child);
                    }
                }
            } else {
                let child = base.join(segment);
                if fs::symlink_metadata(&child).is_ok() && (last || child.is_dir()) {
                    next.push(child);
                }
            }
        }
        next.dedup();
        current = next;
    }
    current
}

/// `Path.rglob(pattern)` for a single-segment pattern: every match below
/// `root`, excluding `root` itself, never entering directory links.
pub fn rglob(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for directory in directories(root) {
        for child in children(&directory) {
            if child
                .file_name()
                .is_some_and(|n| fnmatch(&n.to_string_lossy(), pattern))
            {
                out.push(child);
            }
        }
    }
    out
}

/// `uuid.uuid4().hex`.
pub fn uuid4() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut random) = fs::File::open("/dev/urandom") {
        let _ = random.read_exact(&mut bytes);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `repr(list_of_str)`.
pub fn repr_list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| py::repr_str(s))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn signal_name(signal: i32) -> String {
    let name = match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 if cfg!(target_os = "linux") => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 if cfg!(target_os = "macos") => "SIGBUS",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 if cfg!(target_os = "linux") => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => return format!("{signal}"),
    };
    format!("<Signals.{name}: {signal}>")
}

/// `str(subprocess.CalledProcessError(code, argv))`.
pub fn called_process_error(argv: &[String], code: i32) -> String {
    if code < 0 {
        format!(
            "Command '{}' died with {}.",
            repr_list(argv),
            signal_name(-code)
        )
    } else {
        format!(
            "Command '{}' returned non-zero exit status {code}.",
            repr_list(argv)
        )
    }
}

/// `subprocess` text mode: strict UTF-8, universal newlines.
pub fn text_mode(data: &[u8]) -> Result<String> {
    Ok(decode(data)?.replace("\r\n", "\n").replace('\r', "\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pathlib_and_python_text_semantics() {
        assert_eq!(join(Path::new("/a"), "./b//c/"), PathBuf::from("/a/b/c"));
        assert_eq!(join(Path::new("/a"), "/x"), PathBuf::from("/x"));
        assert!(fnmatch("auth-alpha", "auth-*"));
        assert!(fnmatch(".hidden.rs", "*.rs"));
        assert!(fnmatch("a1", "a[0-9]"));
        assert!(!fnmatch("ab", "a[!b]"));
        assert_eq!(
            called_process_error(&["cargo".into(), "it's".into()], 101),
            "Command '['cargo', \"it's\"]' returned non-zero exit status 101."
        );
        assert_eq!(
            called_process_error(&["x".into()], -9),
            "Command '['x']' died with <Signals.SIGKILL: 9>."
        );
        let error = std::io::Error::from_raw_os_error(2);
        assert_eq!(
            os_error(&error, Some(Path::new("/missing"))),
            "[Errno 2] No such file or directory: '/missing'"
        );
        assert_eq!(text_mode(b"a\r\nb\rc").unwrap(), "a\nb\nc");
        let id = uuid4();
        assert_eq!(id.len(), 32);
        assert_eq!(&id[12..13], "4");
    }

    #[test]
    fn globbing_never_enters_directory_links() {
        let root = std::env::temp_dir().join(format!("pathx-{}", uuid4()));
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/x.rs"), "").unwrap();
        fs::write(root.join("a/b/y.rs"), "").unwrap();
        std::os::unix::fs::symlink(root.join("a"), root.join("link")).unwrap();
        let mut found = rglob(&root, "*.rs");
        found.sort();
        assert_eq!(found, vec![root.join("a/b/y.rs"), root.join("a/x.rs")]);
        assert_eq!(glob(&root, "a/*/y.rs"), vec![root.join("a/b/y.rs")]);
        assert_eq!(glob(&root, "a/missing"), Vec::<PathBuf>::new());
        fs::remove_dir_all(&root).unwrap();
    }

    /// `copytree` into an existing destination never writes through a link it finds there.
    #[test]
    fn copytree_never_writes_through_a_destination_link() {
        let root = std::env::temp_dir().join(format!("pathx-copy-{}", uuid4()));
        let (source, outside, destination) =
            (root.join("source"), root.join("outside"), root.join("dest"));
        fs::create_dir_all(source.join("sub")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::write(source.join("file"), "copied").unwrap();
        fs::write(source.join("sub/inner"), "copied").unwrap();
        fs::write(outside.join("target"), "host").unwrap();
        std::os::unix::fs::symlink(outside.join("target"), destination.join("file")).unwrap();
        std::os::unix::fs::symlink(&outside, destination.join("sub")).unwrap();
        assert!(copytree(&source, &destination).is_err());
        assert_eq!(fs::read(outside.join("target")).unwrap(), b"host");
        assert!(!outside.join("inner").exists());
        fs::remove_dir_all(&root).unwrap();
    }
}
