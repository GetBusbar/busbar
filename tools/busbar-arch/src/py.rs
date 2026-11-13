//! Small helpers that reproduce the observable behaviour of the Python checker:
//! `repr` of strings and lists, `pathlib` joining and `Path.resolve()`, and the
//! text of `OSError` / `CalledProcessError`. They exist so refusal messages stay
//! identical while both implementations run side by side.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::refuse::{Result, Rule, Violation};

/// Python `repr(str)`.
pub fn repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python `repr(list_of_str)`.
pub fn repr_list<S: AsRef<str>>(values: &[S]) -> String {
    let items: Vec<String> = values.iter().map(|v| repr(v.as_ref())).collect();
    format!("[{}]", items.join(", "))
}

/// `pathlib.Path(base) / relative`: absolute `relative` replaces `base`, `.`
/// components and repeated separators disappear, `..` is kept.
pub fn join(base: &Path, relative: impl AsRef<Path>) -> PathBuf {
    normalize(&base.join(relative))
}

/// The component normalisation pathlib applies on construction.
pub fn normalize(path: &Path) -> PathBuf {
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

/// `Path.resolve()` (non-strict): absolute, symlinks of existing parts resolved,
/// `..` applied after the previous component was resolved.
pub fn resolve(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut current = PathBuf::from("/");
    let mut existing = true;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(name) => {
                let next = current.join(name);
                if existing {
                    match std::fs::canonicalize(&next) {
                        Ok(real) => current = real,
                        Err(_) => {
                            existing = false;
                            current = next;
                        }
                    }
                } else {
                    current = next;
                }
            }
        }
    }
    current
}

/// `str(path)`.
pub fn s(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The text Python prints for an `OSError` about `path`.
pub fn os_error(error: &std::io::Error, path: &Path) -> Violation {
    let text = match error.raw_os_error() {
        Some(errno) => {
            let full = error.to_string();
            let strerror = full
                .strip_suffix(&format!(" (os error {errno})"))
                .unwrap_or(&full)
                .to_string();
            format!("[Errno {errno}] {strerror}: {}", repr(&s(path)))
        }
        None => format!("{error}: {}", repr(&s(path))),
    };
    Violation::new(Rule::Io, text)
}

pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| os_error(&e, path))
}

pub fn read_text(path: &Path) -> Result<String> {
    let bytes = read_bytes(path)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        Violation::new(
            Rule::Parse,
            format!("'utf-8' codec can't decode {}", repr(&s(path))),
        )
    })?;
    // Python text mode uses universal newlines.
    Ok(text.replace("\r\n", "\n").replace('\r', "\n"))
}

/// `tomllib.load(open(path, 'rb'))`.
pub fn read_toml(path: &Path) -> Result<toml::Table> {
    let bytes = read_bytes(path)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Violation::new(Rule::Parse, format!("invalid UTF-8 in {}", s(path))))?;
    parse_toml(&text, path)
}

pub fn parse_toml(text: &str, path: &Path) -> Result<toml::Table> {
    text.parse::<toml::Table>().map_err(|e| {
        Violation::new(
            Rule::Parse,
            format!(
                "invalid TOML in {}: {}",
                s(path),
                e.message().trim_end_matches('\n')
            ),
        )
    })
}

pub fn read_json(path: &Path) -> Result<serde_json::Value> {
    let text = read_text(path)?;
    serde_json::from_str(&text).map_err(|e| Violation::new(Rule::Parse, e.to_string()))
}

pub fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn argv_repr(argv: &[String]) -> String {
    repr_list(argv)
}

fn signal_name(signal: i32) -> String {
    let name = match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => return format!("{signal}"),
    };
    format!("<Signals.{name}: {signal}>")
}

/// `str(subprocess.CalledProcessError)`.
fn status_error(argv: &[String], status: ExitStatus) -> Violation {
    let command = argv_repr(argv);
    let message = match status.code() {
        Some(code) => format!("Command '{command}' returned non-zero exit status {code}."),
        None => {
            #[cfg(unix)]
            let signal = {
                use std::os::unix::process::ExitStatusExt;
                status.signal().unwrap_or(0)
            };
            #[cfg(not(unix))]
            let signal = 0;
            format!("Command '{command}' died with {}.", signal_name(signal))
        }
    };
    Violation::new(Rule::Command, message)
}

/// A child command; stdout captured or inherited, stderr always inherited.
pub struct Cmd {
    pub argv: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env_remove: Vec<String>,
    pub env_set: Vec<(String, String)>,
}

impl Cmd {
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Cmd {
            argv: argv
                .into_iter()
                .map(|a| a.as_ref().to_string_lossy().into_owned())
                .collect(),
            cwd: None,
            env_remove: Vec::new(),
            env_set: Vec::new(),
        }
    }

    pub fn cwd(mut self, cwd: &Path) -> Self {
        self.cwd = Some(cwd.to_path_buf());
        self
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.argv[0]);
        command.args(&self.argv[1..]);
        if let Some(cwd) = &self.cwd {
            command.current_dir(cwd);
        }
        for key in &self.env_remove {
            command.env_remove(key);
        }
        for (key, value) in &self.env_set {
            command.env(key, value);
        }
        command
    }

    fn spawn_error(&self, error: std::io::Error) -> Violation {
        os_error(&error, Path::new(&self.argv[0]))
    }

    /// `subprocess.check_output(argv, text=True)`.
    pub fn output(&self) -> Result<String> {
        let output = self
            .command()
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .map_err(|e| self.spawn_error(e))?;
        if !output.status.success() {
            return Err(status_error(&self.argv, output.status));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// `subprocess.run(argv, check=True)` with inherited output (sent to stderr,
    /// so stdout stays the receipt).
    pub fn run(&self) -> Result<()> {
        let status = self
            .command()
            .stdin(Stdio::null())
            .stdout(std::io::stderr())
            .status()
            .map_err(|e| self.spawn_error(e))?;
        if !status.success() {
            return Err(status_error(&self.argv, status));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reprs_match_python() {
        assert_eq!(repr("a"), "'a'");
        assert_eq!(repr("it's"), "\"it's\"");
        assert_eq!(
            repr_list(&["test-seal", "test-support"]),
            "['test-seal', 'test-support']"
        );
        assert_eq!(repr_list::<&str>(&[]), "[]");
    }

    #[test]
    fn joins_like_pathlib() {
        assert_eq!(join(Path::new("/a"), "./b//c"), PathBuf::from("/a/b/c"));
        assert_eq!(join(Path::new("/a"), "../b"), PathBuf::from("/a/../b"));
        assert_eq!(join(Path::new("/a"), "/x"), PathBuf::from("/x"));
    }

    #[test]
    fn resolves_missing_tails() {
        let dir = std::env::temp_dir();
        let real = std::fs::canonicalize(&dir).unwrap();
        assert_eq!(
            resolve(&dir.join("missing-xyz/../other")),
            real.join("other")
        );
    }

    #[test]
    fn command_errors_match_python() {
        let error = Cmd::new(["false"]).run().unwrap_err();
        assert_eq!(
            error.message,
            "Command '['false']' returned non-zero exit status 1."
        );
    }

    #[test]
    fn missing_files_match_python() {
        let error = read_text(Path::new("/nonexistent/.busbar-ref")).unwrap_err();
        assert_eq!(
            error.message,
            "[Errno 2] No such file or directory: '/nonexistent/.busbar-ref'"
        );
    }
}
