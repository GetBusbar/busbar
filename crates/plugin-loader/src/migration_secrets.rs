// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One-time migration of literal credential bytes into private file SecretRefs.
//! This module is never used by serving or secret resolution.
use std::path::Path;

/// Externalize bytes exactly once for a public config site. Existing differing or insecure
/// artifacts are refused; callers must not report `bytes` or expand environment substitutions.
/// Windows requires a manually provisioned private file because this writer cannot prove its ACL.
#[cold]
#[inline(never)]
pub fn externalize(
    config_path: &Path,
    site: &str,
    settings_path: &[String],
    bytes: &[u8],
) -> Result<String, String> {
    #[cfg(unix)]
    {
        unix::externalize(config_path, site, settings_path, bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (config_path, site, settings_path, bytes);
        Err("automatic secret migration cannot establish a private file ACL on this platform; create a private credential file using your platform's access controls and replace the literal setting with an explicit file SecretRef before retrying".into())
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Component, PathBuf};
    use zeroize::Zeroizing;

    const DIRECTORY: &str = ".busbar-migrated-secrets";

    fn failure(stage: &str, error: impl std::fmt::Display) -> String {
        format!("cannot externalize migration secret ({stage}): {error}; source configuration was not modified")
    }

    fn name(value: &OsStr) -> Result<CString, String> {
        CString::new(value.as_bytes()).map_err(|_| failure("path", "NUL in path"))
    }

    fn open_at(
        dir: &File,
        name: &CStr,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> std::io::Result<File> {
        // SAFETY: the descriptor and NUL-terminated name remain valid for this call. A
        // successful open returns a fresh owned descriptor, transferred exactly once to File.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // SAFETY: successful openat returned this fresh descriptor.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn parent(config_path: &Path) -> Result<(PathBuf, File), String> {
        let absolute = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| failure("launch directory", error))?
                .join(config_path)
        };
        if absolute
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(failure(
                "path",
                "use an absolute config path without '..' components",
            ));
        }
        let directory = absolute
            .parent()
            .ok_or_else(|| failure("path", "config needs a parent directory"))?;
        let mut opened = File::open("/").map_err(|error| failure("root directory", error))?;
        for component in directory.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(value) => {
                    opened = open_at(
                        &opened,
                        &name(value)?,
                        libc::O_RDONLY | libc::O_DIRECTORY,
                        0,
                    )
                    .map_err(|error| failure("config directory (symlinks are refused)", error))?;
                }
                _ => return Err(failure("path", "unsupported config path component")),
            }
        }
        let config_name = absolute
            .file_name()
            .ok_or_else(|| failure("path", "missing config filename"))?;
        let source = open_at(
            &opened,
            &name(config_name)?,
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )
        .map_err(|error| failure("source config (symlinks are refused)", error))?;
        if !source
            .metadata()
            .map_err(|error| failure("source config metadata", error))?
            .is_file()
        {
            return Err(failure("source config", "expected a regular file"));
        }
        Ok((absolute, opened))
    }

    fn private(file: &File, directory: bool) -> Result<(), String> {
        let metadata = file
            .metadata()
            .map_err(|error| failure("artifact metadata", error))?;
        // SAFETY: geteuid has no arguments or memory preconditions.
        let owner = unsafe { libc::geteuid() };
        let expected = if directory { 0o700 } else { 0o600 };
        if metadata.uid() != owner
            || metadata.mode() & 0o7777 != expected
            || (directory && !metadata.is_dir())
            || (!directory && (!metadata.is_file()))
        {
            return Err(failure("artifact permissions", "expected a current-user-owned directory mode0700 or regular file mode0600; fix the artifact privately before retrying"));
        }
        Ok(())
    }

    fn existing(directory: &File, final_name: &CStr, bytes: &[u8]) -> Result<bool, String> {
        let mut file = match open_at(directory, final_name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(failure("existing artifact (symlinks are refused)", error)),
        };
        private(&file, false)?;
        let mut stored = Zeroizing::new(Vec::new());
        // Limit reads even if another process changes a file while it is being checked.
        Read::by_ref(&mut file)
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut stored)
            .map_err(|error| failure("existing artifact read", error))?;
        private(&file, false)?;
        if stored.as_slice() != bytes {
            return Err(failure("existing artifact", "this site already has different credential bytes; no file was overwritten; provision a separate private file and use an explicit file SecretRef"));
        }
        file.sync_all()
            .map_err(|error| failure("existing artifact sync", error))?;
        Ok(true)
    }

    struct Temporary<'a> {
        directory: &'a File,
        name: CString,
    }

    impl Drop for Temporary<'_> {
        fn drop(&mut self) {
            // SAFETY: directory and name outlive this call; unlinkat removes only our
            // create_new temporary entry, never follows a symlink or touches the final name.
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }

    pub(super) fn externalize(
        config_path: &Path,
        site: &str,
        settings_path: &[String],
        bytes: &[u8],
    ) -> Result<String, String> {
        let (absolute, parent) = parent(config_path)?;
        // Public site identity only: never derive an artifact's name from its secret bytes.
        let mut identity = Vec::new();
        for part in std::iter::once(
            absolute
                .file_name()
                .expect("checked config filename")
                .as_bytes(),
        )
        .chain(std::iter::once(site.as_bytes()))
        .chain(settings_path.iter().map(|part| part.as_bytes()))
        {
            identity.extend_from_slice(&(part.len() as u64).to_le_bytes());
            identity.extend_from_slice(part);
        }
        let final_name = format!("{}.secret", crate::sign::sha256_hex(&identity));
        let output = absolute
            .parent()
            .expect("checked config parent")
            .join(DIRECTORY)
            .join(&final_name);
        let output = output
            .to_str()
            .ok_or_else(|| failure("path", "output path must be UTF-8"))?
            .to_owned();
        let directory_name = name(OsStr::new(DIRECTORY))?;
        // SAFETY: parent is pinned open and directory_name is a valid C string. mkdirat
        // creates only this single entry; an existing entry is subsequently opened without following links.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), directory_name.as_ptr(), 0o700) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(failure("private directory creation", error));
            }
        }
        let directory = open_at(
            &parent,
            &directory_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .map_err(|error| failure("private directory (symlinks are refused)", error))?;
        private(&directory, true)?;
        parent
            .sync_all()
            .map_err(|error| failure("config directory sync", error))?;
        let final_name = name(OsStr::new(&final_name))?;
        if existing(&directory, &final_name, bytes)? {
            directory
                .sync_all()
                .map_err(|error| failure("private directory sync", error))?;
            return Ok(output);
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random)
            .map_err(|_| failure("temporary name", "secure randomness unavailable"))?;
        let temporary_name = name(OsStr::new(&format!(".pending-{}", hex::encode(random))))?;
        let mut file = open_at(
            &directory,
            &temporary_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .map_err(|error| failure("temporary file creation", error))?;
        let temporary = Temporary {
            directory: &directory,
            name: temporary_name,
        };
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| failure("temporary file permissions", error))?;
        private(&file, false)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| failure("temporary file write/sync", error))?;
        // SAFETY: both entries are relative to the same pinned private directory. linkat
        // atomically publishes a hard link and refuses an existing final entry; no overwrite.
        if unsafe {
            libc::linkat(
                directory.as_raw_fd(),
                temporary.name.as_ptr(),
                directory.as_raw_fd(),
                final_name.as_ptr(),
                0,
            )
        } < 0
        {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(failure("atomic publication", error));
            }
            // A concurrent/retried migration may have published identical bytes first.
            existing(&directory, &final_name, bytes)?;
        }
        drop(file);
        drop(temporary);
        directory
            .sync_all()
            .map_err(|error| failure("private directory sync", error))?;
        Ok(output)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().canonicalize().unwrap();
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let directory = base.join(format!("busbar-migration-secret-{}", hex::encode(random)));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("config.yaml"), b"original config\n").unwrap();
            Self(directory)
        }
        fn config(&self) -> PathBuf {
            self.0.join("config.yaml")
        }
        fn write(&self, bytes: &[u8]) -> Result<String, String> {
            externalize(
                &self.config(),
                "auth:example",
                &["service_password".into()],
                bytes,
            )
        }
        fn secret_dir(&self) -> PathBuf {
            self.0.join(".busbar-migrated-secrets")
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn literal_bytes_are_private_and_exact_without_modifying_source() {
        let fixture = Fixture::new();
        let bytes = b"${LITERAL_SECRET}\nsecond line\r\n\0tail";
        let output = PathBuf::from(fixture.write(bytes).unwrap());
        assert!(output.is_absolute());
        assert_eq!(std::fs::read(&output).unwrap(), bytes);
        assert_eq!(
            std::fs::read(fixture.config()).unwrap(),
            b"original config\n"
        );
        assert_eq!(std::fs::metadata(&output).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(
            std::fs::metadata(fixture.secret_dir()).unwrap().mode() & 0o7777,
            0o700
        );
        assert_eq!(std::fs::read_dir(fixture.secret_dir()).unwrap().count(), 1);
        assert!(!output.to_str().unwrap().contains("LITERAL_SECRET"));
        assert!(!output
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("auth:example"));
    }

    #[test]
    fn same_site_retry_reuses_exact_secure_artifact_without_rewriting() {
        let fixture = Fixture::new();
        let first = fixture.write(b"credential").unwrap();
        let inode = std::fs::metadata(&first).unwrap().ino();
        assert_eq!(fixture.write(b"credential").unwrap(), first);
        assert_eq!(std::fs::metadata(&first).unwrap().ino(), inode);
        assert_eq!(std::fs::read_dir(fixture.secret_dir()).unwrap().count(), 1);
    }

    #[test]
    fn changed_secret_is_refused_without_overwrite_or_literal_diagnostics() {
        let fixture = Fixture::new();
        let path = fixture.write(b"old-private-value").unwrap();
        let error = fixture.write(b"new-private-value").unwrap_err();
        assert!(error.contains("different credential bytes"));
        assert!(!error.contains("old-private-value") && !error.contains("new-private-value"));
        assert_eq!(std::fs::read(path).unwrap(), b"old-private-value");
        assert_eq!(std::fs::read_dir(fixture.secret_dir()).unwrap().count(), 1);
    }

    #[test]
    fn public_site_identity_is_unambiguous_and_not_derived_from_secret() {
        let fixture = Fixture::new();
        let one = externalize(&fixture.config(), "auth:example", &["a/b".into()], b"same").unwrap();
        let two = externalize(
            &fixture.config(),
            "auth:example",
            &["a".into(), "b".into()],
            b"same",
        )
        .unwrap();
        let three = externalize(&fixture.config(), "auth:other", &["a/b".into()], b"same").unwrap();
        assert_ne!(one, two);
        assert_ne!(one, three);
        std::fs::write(fixture.0.join("other.yaml"), b"other config").unwrap();
        let four = externalize(
            &fixture.0.join("other.yaml"),
            "auth:example",
            &["a/b".into()],
            b"same",
        )
        .unwrap();
        assert_ne!(one, four);
    }

    #[test]
    fn symlinked_private_directory_and_config_components_are_refused() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        symlink(&other.0, fixture.secret_dir()).unwrap();
        assert!(fixture.write(b"credential").is_err());
        assert_eq!(std::fs::read_dir(&other.0).unwrap().count(), 1);
        std::fs::remove_file(fixture.secret_dir()).unwrap();
        symlink(&other.0, fixture.0.join("linked-parent")).unwrap();
        assert!(externalize(
            &fixture.0.join("linked-parent/config.yaml"),
            "site",
            &[],
            b"credential"
        )
        .is_err());
        symlink(other.config(), fixture.0.join("linked-config.yaml")).unwrap();
        assert!(externalize(
            &fixture.0.join("linked-config.yaml"),
            "site",
            &[],
            b"credential"
        )
        .is_err());
    }

    #[test]
    fn symlinked_file_is_refused_even_when_target_bytes_and_mode_match() {
        let fixture = Fixture::new();
        let path = fixture.write(b"credential").unwrap();
        let target = fixture.0.join("outside");
        std::fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        assert!(fixture.write(b"credential").is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"credential");
    }

    #[test]
    fn insecure_existing_directory_and_file_are_refused() {
        let fixture = Fixture::new();
        let path = fixture.write(b"credential").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(fixture.write(b"credential").is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(fixture.secret_dir(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(fixture.write(b"credential").is_err());
        std::fs::set_permissions(fixture.secret_dir(), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"credential");
    }

    #[test]
    fn retry_after_publication_before_temp_unlink_reuses_the_durable_artifact() {
        let fixture = Fixture::new();
        let path = fixture.write(b"credential").unwrap();
        // Model a crash after atomic publication, before the private temporary alias was removed.
        std::fs::hard_link(&path, fixture.secret_dir().join(".pending-interrupted")).unwrap();
        assert_eq!(fixture.write(b"credential").unwrap(), path);
        assert_eq!(std::fs::read(path).unwrap(), b"credential");
    }

    #[test]
    fn nonregular_existing_file_is_refused_without_blocking() {
        let fixture = Fixture::new();
        let path = fixture.write(b"credential").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(fixture.write(b"credential").is_err());
    }
}
