// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE path-confinement helper for names that reach the filesystem from outside the process
//! (an admin API file name, an archive entry, a directory listing of an operator-shared dir).
//!
//! A name is joined under an allowed root only after it passes [`check_relative`] (no absolute,
//! prefix, `..` or NUL component), the deepest existing ancestor of its parent is canonicalised
//! and must still lie under the canonical root (a planted directory link cannot carry the name out:
//! zip-slip), and the final component must not itself be a link. [`ConfinedRoot::open`] then opens
//! with `O_NOFOLLOW` where the platform has it and checks that the handle is the very inode the
//! name resolved to, so a link swapped in after resolution is refused rather than followed.
//!
//! A path that is internal or operator-only (the directory the process just wrote into, a
//! configured data dir) is not confined: it is named with [`TrustedPath`], so the trust decision
//! is a typed, greppable statement at the call site rather than an ignore comment.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

/// Why a name was refused. Each lexical escape form has its own variant so callers and tests can
/// tell them apart; [`ConfinedPathError::Io`] carries a genuine filesystem failure (e.g. NotFound).
#[derive(Debug)]
#[non_exhaustive]
pub enum ConfinedPathError {
    /// The name has no normal component (empty, or only `.`).
    Empty,
    /// The name is absolute (a root component).
    Absolute,
    /// The name contains a `..` component.
    ParentTraversal,
    /// The name carries a platform prefix (a Windows drive or UNC prefix).
    Prefix,
    /// The name contains a NUL byte.
    Nul,
    /// The name resolves outside the root through a linked directory.
    Escapes,
    /// The final component is a symbolic link (or was swapped for something else after resolution).
    Symlink,
    /// A filesystem operation failed.
    Io(io::Error),
}

impl ConfinedPathError {
    /// The `io::ErrorKind` this refusal maps to: confinement refusals are `PermissionDenied`
    /// (the name names something the caller may not reach), lexical ones `InvalidInput`.
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Empty | Self::Absolute | Self::ParentTraversal | Self::Prefix | Self::Nul => {
                io::ErrorKind::InvalidInput
            }
            Self::Escapes | Self::Symlink => io::ErrorKind::PermissionDenied,
            Self::Io(error) => error.kind(),
        }
    }
}

impl fmt::Display for ConfinedPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("path names nothing"),
            Self::Absolute => f.write_str("path is absolute"),
            Self::ParentTraversal => f.write_str("path contains `..`"),
            Self::Prefix => f.write_str("path carries a platform prefix"),
            Self::Nul => f.write_str("path contains a NUL byte"),
            Self::Escapes => f.write_str("path resolves outside its root"),
            Self::Symlink => f.write_str("path is a symbolic link"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ConfinedPathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ConfinedPathError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ConfinedPathError> for io::Error {
    fn from(error: ConfinedPathError) -> Self {
        match error {
            ConfinedPathError::Io(error) => error,
            other => io::Error::new(other.kind(), other),
        }
    }
}

/// Refuse a name that is empty, absolute, prefixed, contains `..` or a NUL byte. `.` components
/// are ignored. This is lexical only; [`ConfinedRoot`] adds the filesystem checks.
pub fn check_relative(relative: &Path) -> Result<(), ConfinedPathError> {
    if relative.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(ConfinedPathError::Nul);
    }
    let mut normal = false;
    for component in relative.components() {
        match component {
            Component::Prefix(_) => return Err(ConfinedPathError::Prefix),
            Component::RootDir => return Err(ConfinedPathError::Absolute),
            Component::ParentDir => return Err(ConfinedPathError::ParentTraversal),
            Component::CurDir => {}
            Component::Normal(_) => normal = true,
        }
    }
    if normal {
        Ok(())
    } else {
        Err(ConfinedPathError::Empty)
    }
}

/// An allowed root, held canonical. Names join under it only through [`ConfinedRoot::resolve`]
/// or [`ConfinedRoot::open`].
#[derive(Debug, Clone)]
pub struct ConfinedRoot {
    root: PathBuf,
}

impl ConfinedRoot {
    /// Canonicalise `root` (which must be an existing directory). The root itself is the caller's
    /// trust decision (operator configuration or a directory the process owns).
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ConfinedPathError> {
        let root = std::fs::canonicalize(root)?;
        if !std::fs::metadata(&root)?.is_dir() {
            return Err(ConfinedPathError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "confinement root is not a directory",
            )));
        }
        Ok(Self { root })
    }

    /// The canonical root.
    pub fn as_path(&self) -> &Path {
        &self.root
    }

    /// Join `relative` under the root: lexically checked, its existing parent canonicalised and
    /// still under the root, its final component not a link. A missing final component (or
    /// missing parents) still resolves, so callers can create it.
    pub fn resolve(&self, relative: impl AsRef<Path>) -> Result<PathBuf, ConfinedPathError> {
        let relative = relative.as_ref();
        check_relative(relative)?;
        let names: Vec<_> = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        let Some((last, parents)) = names.split_last() else {
            return Err(ConfinedPathError::Empty);
        };
        let mut existing = self.root.clone();
        let mut missing = Vec::new();
        for name in parents {
            if missing.is_empty() {
                existing.push(name);
                match std::fs::symlink_metadata(&existing) {
                    Ok(_) => continue,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        existing.pop();
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            missing.push(*name);
        }
        let mut path = std::fs::canonicalize(&existing)?;
        if !path.starts_with(&self.root) {
            return Err(ConfinedPathError::Escapes);
        }
        path.extend(missing);
        path.push(last);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => Err(ConfinedPathError::Symlink),
            Ok(_) => Ok(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(path),
            Err(error) => Err(error.into()),
        }
    }

    /// Open `relative` read-only under the root, never following a link at the final component
    /// and refusing a handle that is not the inode the name resolved to.
    pub fn open(&self, relative: impl AsRef<Path>) -> Result<File, ConfinedPathError> {
        let path = self.resolve(relative)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NONBLOCK: a FIFO swapped in under an archive name cannot stall the open.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            #[cfg(unix)]
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(ConfinedPathError::Symlink)
            }
            Err(error) => return Err(error.into()),
        };
        self.same_entry(&path, &file)?;
        Ok(file)
    }

    /// The opened handle must be the entry `path` names now, and `path`'s parent must still
    /// resolve under the root: a swap between resolution and open refuses.
    fn same_entry(&self, path: &Path, file: &File) -> Result<(), ConfinedPathError> {
        let named = std::fs::symlink_metadata(path)?;
        if named.file_type().is_symlink() {
            return Err(ConfinedPathError::Symlink);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = file.metadata()?;
            if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
                return Err(ConfinedPathError::Symlink);
            }
        }
        #[cfg(not(unix))]
        let _ = file;
        let parent = path.parent().ok_or(ConfinedPathError::Escapes)?;
        if !std::fs::canonicalize(parent)?.starts_with(&self.root) {
            return Err(ConfinedPathError::Escapes);
        }
        Ok(())
    }
}

/// A path that is internal or operator-only — a directory the process itself just created or
/// wrote into, or one named by operator configuration — and so is deliberately NOT confined.
/// Constructing one is the audit point: every `TrustedPath::internal` call site states why its
/// path cannot carry outside input.
#[derive(Debug, Clone, Copy)]
pub struct TrustedPath<'a>(&'a Path);

impl<'a> TrustedPath<'a> {
    /// Name an internal or operator-only path. Never construct one from request, plugin or
    /// archive data; confine those with [`ConfinedRoot`].
    pub fn internal(path: &'a Path) -> Self {
        Self(path)
    }

    /// The path.
    pub fn as_path(&self) -> &'a Path {
        self.0
    }

    /// Open the directory read-only (for a durability barrier: `sync_all` on the handle). Refuses
    /// a path that is not a directory.
    pub fn open_dir(&self) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC);
        }
        let file = options.open(self.0)?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusted directory is not a directory",
            ));
        }
        Ok(file)
    }
}

#[cfg(test)]
#[path = "tests/confined_path_tests.rs"]
mod tests;
