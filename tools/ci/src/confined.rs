//! Path confinement for names the controller did not choose: archive member
//! names, directory listings of candidate-produced trees, configured roots.
//!
//! The controller is a std-only workspace built from `tools/ci` alone (see
//! `build-controller.sh`), so it cannot link core's
//! `busbar_contract::confined_path`; this module is its std-only counterpart
//! with the same contract and the same escape matrix in its tests:
//!
//! - a name joins under a root only after [`check_relative`] (no absolute,
//!   prefix, `..` or NUL component);
//! - the deepest existing ancestor is canonicalised and must still lie under
//!   the canonical root, so a planted directory link cannot carry a name out
//!   (zip-slip);
//! - the final component is never a link: opens and creates use `O_NOFOLLOW`
//!   and the handle must be the inode the name resolved to.
//!
//! Paths that are internal or operator-only are named with [`Trusted`], so the
//! trust decision is a typed statement at the call site, not an ignore comment.
use crate::proc;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

/// Why a name was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No normal component (empty, or only `.`).
    Empty,
    /// A root component.
    Absolute,
    /// A `..` component.
    ParentTraversal,
    /// A platform prefix component.
    Prefix,
    /// A NUL byte.
    Nul,
    /// Resolves outside the root through a linked directory.
    Escapes,
    /// The final component is a link (or changed after resolution).
    Symlink,
    /// A filesystem operation failed.
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("path names nothing"),
            Self::Absolute => f.write_str("path is absolute"),
            Self::ParentTraversal => f.write_str("path contains `..`"),
            Self::Prefix => f.write_str("path carries a platform prefix"),
            Self::Nul => f.write_str("path contains a NUL byte"),
            Self::Escapes => f.write_str("path resolves outside its root"),
            Self::Symlink => f.write_str("path is a symbolic link"),
            Self::Io(error) => f.write_str(error),
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<Error> for String {
    fn from(error: Error) -> Self {
        format!("unsafe path: {error}")
    }
}

/// Refuse an empty, absolute, prefixed, `..`-bearing or NUL-bearing name.
/// `.` components are ignored. Lexical only; [`Root`] adds the filesystem checks.
pub fn check_relative(relative: &Path) -> Result<(), Error> {
    if relative.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(Error::Nul);
    }
    let mut normal = false;
    for component in relative.components() {
        match component {
            Component::Prefix(_) => return Err(Error::Prefix),
            Component::RootDir => return Err(Error::Absolute),
            Component::ParentDir => return Err(Error::ParentTraversal),
            Component::CurDir => {}
            Component::Normal(_) => normal = true,
        }
    }
    if normal { Ok(()) } else { Err(Error::Empty) }
}

/// An allowed root, held canonical.
#[derive(Debug, Clone)]
pub struct Root {
    root: PathBuf,
}

impl Root {
    /// Canonicalise `root`, an existing directory the caller trusts.
    pub fn new(root: &Path) -> Result<Self, Error> {
        let root = fs::canonicalize(root)?;
        if !fs::metadata(&root)?.is_dir() {
            return Err(Error::Io(format!(
                "confinement root is not a directory: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub fn as_path(&self) -> &Path {
        &self.root
    }

    /// Split a checked name into its parents and final component.
    fn split(relative: &Path) -> Result<(Vec<&std::ffi::OsStr>, &std::ffi::OsStr), Error> {
        check_relative(relative)?;
        let mut names: Vec<_> = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        let last = names.pop().ok_or(Error::Empty)?;
        Ok((names, last))
    }

    /// `path` canonicalised, refused unless it is (still) under the root.
    fn inside(&self, path: &Path) -> Result<PathBuf, Error> {
        let real = fs::canonicalize(path)?;
        if real.starts_with(&self.root) {
            Ok(real)
        } else {
            Err(Error::Escapes)
        }
    }

    /// Join `relative` under the root. Missing parents and a missing final
    /// component still resolve (callers create them); a final link refuses.
    pub fn resolve(&self, relative: &Path) -> Result<PathBuf, Error> {
        let (parents, last) = Self::split(relative)?;
        let mut existing = self.root.clone();
        let mut missing = Vec::new();
        for name in parents {
            if missing.is_empty() {
                existing.push(name);
                match fs::symlink_metadata(&existing) {
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        existing.pop();
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            missing.push(name);
        }
        let mut path = self.inside(&existing)?;
        path.extend(missing);
        path.push(last);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::Symlink),
            Ok(_) => Ok(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
            Err(error) => Err(error.into()),
        }
    }

    /// Open `relative` read-only, never through a link.
    pub fn open(&self, relative: &Path) -> Result<File, Error> {
        let path = self.resolve(relative)?;
        let file = Self::nofollow(
            OpenOptions::new().read(true).custom_flags(proc::O_NOFOLLOW),
            &path,
        )?;
        self.same_entry(&path, &file)?;
        Ok(file)
    }

    /// Create `relative` exclusively with `mode`, creating missing parent
    /// directories one at a time inside the root. Never adopts an existing
    /// entry and never writes through a link (zip-slip).
    pub fn create_new(&self, relative: &Path, mode: u32) -> Result<File, Error> {
        let (parents, last) = Self::split(relative)?;
        let mut directory = self.root.clone();
        for name in parents {
            directory.push(name);
            match fs::symlink_metadata(&directory) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    directory = self.inside(&directory)?;
                }
                Ok(metadata) if metadata.is_dir() => {}
                Ok(_) => {
                    return Err(Error::Io(format!(
                        "not a directory: {}",
                        directory.display()
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match fs::create_dir(&directory) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error.into()),
                    }
                    directory = self.inside(&directory)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let path = self.inside(&directory)?.join(last);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(Error::Symlink);
        }
        let file = Self::nofollow(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(proc::O_NOFOLLOW),
            &path,
        )?;
        self.same_entry(&path, &file)?;
        Ok(file)
    }

    fn nofollow(options: &OpenOptions, path: &Path) -> Result<File, Error> {
        options.open(path).map_err(|error| {
            if error.raw_os_error() == Some(proc::ELOOP) {
                Error::Symlink
            } else {
                Error::Io(format!("{}: {error}", path.display()))
            }
        })
    }

    /// The handle must be the entry `path` names now, under the root.
    fn same_entry(&self, path: &Path, file: &File) -> Result<(), Error> {
        let named = fs::symlink_metadata(path)?;
        let held = file.metadata()?;
        if named.file_type().is_symlink() || (held.dev(), held.ino()) != (named.dev(), named.ino())
        {
            return Err(Error::Symlink);
        }
        self.inside(path.parent().ok_or(Error::Escapes)?)?;
        Ok(())
    }
}

/// A path that is internal or operator-only (a directory this controller
/// created, a download it wrote, protected configuration) and is therefore
/// deliberately not confined. Constructing one is the audit point: the call
/// site states why the path cannot carry candidate, archive or request input.
#[derive(Debug, Clone, Copy)]
pub struct Trusted<'a>(&'a Path);

impl<'a> Trusted<'a> {
    pub fn internal(path: &'a Path) -> Self {
        Self(path)
    }

    pub fn as_path(&self) -> &'a Path {
        self.0
    }
}

#[cfg(test)]
#[path = "confined_tests.rs"]
mod tests;
