// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One-time migration of literal credential bytes into private file SecretRefs.
//! This module is never used by serving or secret resolution.
use std::path::Path;

/// Resolve the existing migration artifact identity without touching the filesystem.
/// Only public source/site components enter the name; literal bytes are never hashed into it.
pub fn externalized_path(
    config_path: &Path,
    site: &str,
    settings_path: &[String],
) -> Result<std::path::PathBuf, String> {
    let absolute = if config_path.is_absolute() {
        config_path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| "cannot resolve configuration directory")?
            .join(config_path)
    };
    if absolute
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("migration source path must not contain parent components".into());
    }
    let file = absolute
        .file_name()
        .ok_or("migration source has no filename")?;
    let mut identity = Vec::new();
    for part in std::iter::once(file.as_encoded_bytes())
        .chain(std::iter::once(site.as_bytes()))
        .chain(settings_path.iter().map(|part| part.as_bytes()))
    {
        identity.extend_from_slice(&(part.len() as u64).to_le_bytes());
        identity.extend_from_slice(part);
    }
    let filename = format!("{}.secret", crate::sign::sha256_hex(&identity));
    Ok(absolute
        .parent()
        .ok_or("migration source has no directory")?
        .join(".busbar-migrated-secrets")
        .join(filename))
}

/// Externalize bytes exactly once for a public config site. Existing differing or insecure
/// artifacts are refused; callers must not report `bytes` or expand environment substitutions.
/// Windows creates and verifies a protected current-user-only DACL before writing bytes.
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
    #[cfg(windows)]
    {
        windows::externalize(config_path, site, settings_path, bytes)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (config_path, site, settings_path, bytes);
        Err("automatic secret migration cannot establish a private file ACL on this platform; create a private credential file using your platform's access controls and replace the literal setting with an explicit file SecretRef before retrying".into())
    }
}

#[cfg(unix)]
pub(crate) mod unix {
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
        format!(
            "cannot externalize migration secret ({stage}): {error}; source configuration was not modified"
        )
    }

    pub(crate) fn name(value: &OsStr) -> Result<CString, String> {
        CString::new(value.as_bytes()).map_err(|_| failure("path", "NUL in path"))
    }

    pub(crate) fn open_at(
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

    pub(crate) fn parent_directory(config_path: &Path) -> Result<(PathBuf, File), String> {
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
        Ok((absolute, opened))
    }

    fn parent(config_path: &Path) -> Result<(PathBuf, File), String> {
        let (absolute, opened) = parent_directory(config_path)?;
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
            return Err(failure(
                "artifact permissions",
                "expected a current-user-owned directory mode0700 or regular file mode0600; fix the artifact privately before retrying",
            ));
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
            return Err(failure(
                "existing artifact",
                "this site already has different credential bytes; no file was overwritten; provision a separate private file and use an explicit file SecretRef",
            ));
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
        let output = super::externalized_path(&absolute, site, settings_path)?;
        let final_name = output
            .file_name()
            .ok_or_else(|| failure("path", "missing artifact filename"))?
            .to_os_string();
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
        let final_name = name(&final_name)?;
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

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::durable::documents::{windows_identity, windows_parent, windows_security};
    use std::{
        ffi::c_void,
        fs::{File, OpenOptions},
        io::{self, Read, Write},
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::PathBuf,
    };
    use windows_sys::Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_READ, GENERIC_WRITE,
            INVALID_HANDLE_VALUE, LocalFree,
        },
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            DACL_SECURITY_INFORMATION, GetTokenInformation, IsValidSid, OWNER_SECURITY_INFORMATION,
            SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        Storage::FileSystem::{
            CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            MOVEFILE_WRITE_THROUGH, MoveFileExW,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    use zeroize::Zeroizing;

    const DIRECTORY: &str = ".busbar-migrated-secrets";
    fn failure(stage: &str, error: impl std::fmt::Display) -> String {
        format!(
            "cannot externalize migration secret ({stage}): {error}; source configuration was not modified"
        )
    }
    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a current-user-owned protected private DACL and non-reparse native file boundary",
        )
    }
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value: Vec<_> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(invalid());
        }
        value.push(0);
        Ok(value)
    }
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: successful security conversion APIs return exactly this LocalAlloc allocation.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn local_text(pointer: *const u16) -> io::Result<Vec<u16>> {
        if pointer.is_null() {
            return Err(invalid());
        }
        let mut text = Vec::new();
        for index in 0..1_048_576 {
            // SAFETY: the Win32 conversion contract returns a live NUL-terminated string.
            let value = unsafe { *pointer.add(index) };
            if value == 0 {
                return Ok(text);
            }
            text.push(value);
        }
        Err(invalid())
    }
    fn canonical(descriptor: *mut c_void) -> io::Result<Vec<u16>> {
        let mut text = std::ptr::null_mut();
        // SAFETY: callers supply a native-created self-relative descriptor retained for this call.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut text,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let _owner = Local(text.cast());
        local_text(text)
    }
    fn current_sid() -> io::Result<Vec<u16>> {
        let mut token = std::ptr::null_mut();
        // SAFETY: this requests only query access to the current process token.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: OpenProcessToken returned a fresh owned handle, closed once by OwnedHandle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut needed = 0;
        // SAFETY: null output queries the native TokenUser record size.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        if needed < std::mem::size_of::<TOKEN_USER>() as u32 || needed > 1_048_576 {
            return Err(invalid());
        }
        // usize elements guarantee native TOKEN_USER alignment and initialized SID workspace.
        let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0usize; words];
        // SAFETY: initialized aligned storage is at least needed bytes and remains live through SID conversion.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the native call initialized a complete TOKEN_USER in the checked allocation.
        let user = unsafe { std::ptr::read(storage.as_ptr().cast::<TOKEN_USER>()) };
        // SAFETY: the SID is part of the live native TokenUser allocation.
        if unsafe { IsValidSid(user.User.Sid) } == 0 {
            return Err(invalid());
        }
        let mut text = std::ptr::null_mut();
        // SAFETY: valid native SID and writable result pointer remain live.
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _owner = Local(text.cast());
        local_text(text)
    }
    struct PrivateSecurity {
        descriptor: Local,
        canonical: Vec<u16>,
    }
    impl PrivateSecurity {
        fn new(sid: &[u16], directory: bool) -> io::Result<Self> {
            let sid = String::from_utf16(sid).map_err(|_| invalid())?;
            let flags = if directory { "OICI" } else { "" };
            let mut sddl: Vec<_> = format!("O:{sid}D:P(A;{flags};FA;;;{sid})")
                .encode_utf16()
                .collect();
            sddl.push(0);
            let mut descriptor = std::ptr::null_mut();
            // SAFETY: SDDL is NUL-terminated and contains only the queried native SID, never credential bytes.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let descriptor = Local(descriptor);
            let canonical = canonical(descriptor.0)?;
            Ok(Self {
                descriptor,
                canonical,
            })
        }
        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.descriptor.0,
                bInheritHandle: 0,
            }
        }
        fn verify(&self, file: &File, directory: bool) -> io::Result<()> {
            let metadata = file.metadata()?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || (directory && !metadata.is_dir())
                || (!directory && !metadata.is_file())
            {
                return Err(invalid());
            }
            let mut security = windows_security(file)?;
            if canonical(security.as_mut_ptr().cast())? != self.canonical {
                return Err(invalid());
            }
            Ok(())
        }
    }
    fn directory(path: &Path) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if !file.metadata()?.is_dir()
            || file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(invalid());
        }
        Ok(file)
    }
    fn exact(file: &mut File, private: &PrivateSecurity, bytes: &[u8]) -> io::Result<()> {
        private.verify(file, false)?;
        let length = bytes.len().checked_add(1).ok_or_else(invalid)?;
        // Allocate once before any secret bytes enter; growth cannot leave retired plaintext buffers.
        let mut stored = Zeroizing::new(vec![0; length]);
        let mut read = 0;
        while read < stored.len() {
            let n = file.read(&mut stored[read..])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        private.verify(file, false)?;
        if !busbar_contract::redacted::constant_time_eq(&stored[..read], bytes) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "this site already has different credential bytes; no file was overwritten",
            ));
        }
        Ok(())
    }
    fn existing(path: &Path, private: &PrivateSecurity, bytes: &[u8]) -> io::Result<bool> {
        let mut file = match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        exact(&mut file, private, bytes)?;
        file.sync_all()?;
        Ok(true)
    }
    struct Temporary {
        path: PathBuf,
        published: bool,
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            if !self.published {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
    pub(super) fn externalize(
        config_path: &Path,
        site: &str,
        settings_path: &[String],
        bytes: &[u8],
    ) -> Result<String, String> {
        // Reject lexical parent traversal before Windows absolute-path normalization.
        let output = super::externalized_path(config_path, site, settings_path)?;
        let output_text = output
            .to_str()
            .ok_or_else(|| failure("path", "output path must be UTF-8"))?
            .to_owned();
        let (absolute, _parents) = windows_parent(config_path)
            .map_err(|error| failure("pinned config directory", error))?;
        let source = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&absolute)
            .map_err(|error| failure("source config", error))?;
        if !source
            .metadata()
            .map_err(|error| failure("source metadata", error))?
            .is_file()
            || source
                .metadata()
                .map_err(|error| failure("source metadata", error))?
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT
                != 0
        {
            return Err(failure("source config", invalid()));
        }
        let sid = current_sid().map_err(|error| failure("current native owner", error))?;
        let private_directory = PrivateSecurity::new(&sid, true)
            .map_err(|error| failure("private directory ACL", error))?;
        let private_file = PrivateSecurity::new(&sid, false)
            .map_err(|error| failure("private file ACL", error))?;
        let directory_path = absolute
            .parent()
            .ok_or_else(|| failure("path", invalid()))?
            .join(DIRECTORY);
        let directory_name = wide(&directory_path).map_err(|error| failure("path", error))?;
        let attributes = private_directory.attributes();
        // SAFETY: pinned ancestor names and a live explicit protected owner-only descriptor remain valid.
        if unsafe { CreateDirectoryW(directory_name.as_ptr(), &attributes) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(failure("private directory creation", error));
            }
        }
        let directory = directory(&directory_path)
            .map_err(|error| failure("private directory boundary", error))?;
        private_directory
            .verify(&directory, true)
            .map_err(|error| failure("private directory ACL", error))?;
        if existing(&output, &private_file, bytes)
            .map_err(|error| failure("existing artifact", error))?
        {
            return Ok(output_text);
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random)
            .map_err(|_| failure("temporary identity", "secure randomness unavailable"))?;
        let mut temporary = Temporary {
            path: directory_path.join(format!(".pending-{}", hex::encode(random))),
            published: false,
        };
        let name = wide(&temporary.path).map_err(|error| failure("temporary path", error))?;
        let attributes = private_file.attributes();
        // SAFETY: CREATE_NEW never opens/overwrites an existing file; the protected owner-only
        // DACL is applied atomically at creation, before the first credential byte is written.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(failure(
                "exclusive temporary creation",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: CreateFileW returned a fresh exclusively owned file handle.
        let mut file = unsafe { File::from_raw_handle(handle) };
        private_file
            .verify(&file, false)
            .map_err(|error| failure("temporary ACL", error))?;
        let identity =
            windows_identity(&file).map_err(|error| failure("temporary identity", error))?;
        if identity[..4]
            != windows_identity(&directory)
                .map_err(|error| failure("private directory identity", error))?[..4]
        {
            return Err(failure(
                "volume boundary",
                "temporary and private directory are not on the same native volume",
            ));
        }
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| failure("temporary write/sync", error))?;
        private_file
            .verify(&file, false)
            .map_err(|error| failure("temporary ACL recheck", error))?;
        let destination = wide(&output).map_err(|error| failure("artifact path", error))?;
        // SAFETY: both leaf names live inside the same pinned, owner-only directory.
        // No COPY_ALLOWED or REPLACE_EXISTING: publication is exclusive and never crosses volumes.
        // WRITE_THROUGH is the documented native move durability barrier; errors are never ignored.
        if unsafe { MoveFileExW(name.as_ptr(), destination.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0
        {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32)
            {
                return Err(failure("exclusive write-through publication", error));
            }
            if !existing(&output, &private_file, bytes)
                .map_err(|error| failure("concurrent artifact", error))?
            {
                return Err(failure(
                    "concurrent artifact",
                    "publication changed before readback",
                ));
            }
            return Ok(output_text);
        }
        temporary.published = true;
        // Keep the original write handle open: its share mode excludes other writers.
        let mut published = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&output)
            .map_err(|error| failure("published artifact readback", error))?;
        if windows_identity(&published).map_err(|error| failure("published identity", error))?
            != identity
        {
            return Err(failure(
                "published identity",
                "published file differs from the flushed private temporary",
            ));
        }
        exact(&mut published, &private_file, bytes)
            .map_err(|error| failure("published artifact verification", error))?;
        file.sync_all()
            .map_err(|error| failure("published artifact sync", error))?;
        private_directory
            .verify(&directory, true)
            .map_err(|error| failure("private directory final ACL", error))?;
        Ok(output_text)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        struct Fixture(PathBuf);
        impl Fixture {
            fn new() -> Self {
                let mut random = [0; 16];
                getrandom::fill(&mut random).unwrap();
                let directory = std::env::temp_dir()
                    .canonicalize()
                    .unwrap()
                    .join(format!("busbar-windows-secret-{}", hex::encode(random)));
                std::fs::create_dir(&directory).unwrap();
                std::fs::write(directory.join("config.yaml"), b"original config").unwrap();
                Self(directory)
            }
            fn config(&self) -> PathBuf {
                self.0.join("config.yaml")
            }
            fn write(&self, bytes: &[u8]) -> Result<String, String> {
                super::externalize(&self.config(), "auth:example", &["password".into()], bytes)
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn literal_artifact_has_owner_only_dacl_and_exact_retry_keeps_identity() {
            let fixture = Fixture::new();
            let bytes = b"${LITERAL}\nsecond line\r\n\0tail";
            let output = fixture.write(bytes).unwrap();
            let file = File::open(&output).unwrap();
            let identity = windows_identity(&file).unwrap();
            let sid = current_sid().unwrap();
            PrivateSecurity::new(&sid, false)
                .unwrap()
                .verify(&file, false)
                .unwrap();
            drop(file);
            let private_directory = fixture.0.join(DIRECTORY);
            PrivateSecurity::new(&sid, true)
                .unwrap()
                .verify(&directory(&private_directory).unwrap(), true)
                .unwrap();
            assert_eq!(std::fs::read(&output).unwrap(), bytes);
            assert_eq!(fixture.write(bytes).unwrap(), output);
            assert_eq!(
                windows_identity(&File::open(&output).unwrap()).unwrap(),
                identity
            );
            assert_eq!(std::fs::read(fixture.config()).unwrap(), b"original config");
            assert_eq!(std::fs::read_dir(private_directory).unwrap().count(), 1);
        }

        #[test]
        fn changed_artifact_is_refused_without_overwrite_or_secret_diagnostics() {
            let fixture = Fixture::new();
            let output = fixture.write(b"old-private-value").unwrap();
            let error = fixture.write(b"new-private-value").unwrap_err();
            assert!(error.contains("different credential bytes"));
            assert!(!error.contains("old-private-value"));
            assert!(!error.contains("new-private-value"));
            assert_eq!(std::fs::read(output).unwrap(), b"old-private-value");
            assert_eq!(
                std::fs::read_dir(fixture.0.join(DIRECTORY))
                    .unwrap()
                    .count(),
                1
            );
        }

        #[test]
        fn inherited_public_directory_dacl_is_refused_before_secret_creation() {
            let fixture = Fixture::new();
            let output_directory = fixture.0.join(DIRECTORY);
            std::fs::create_dir(&output_directory).unwrap();
            assert!(fixture.write(b"private-value").is_err());
            assert_eq!(std::fs::read_dir(output_directory).unwrap().count(), 0);
            assert_eq!(std::fs::read(fixture.config()).unwrap(), b"original config");
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
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
        assert!(
            !output
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains("auth:example")
        );
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
        assert!(
            externalize(
                &fixture.0.join("linked-parent/config.yaml"),
                "site",
                &[],
                b"credential"
            )
            .is_err()
        );
        symlink(other.config(), fixture.0.join("linked-config.yaml")).unwrap();
        assert!(
            externalize(
                &fixture.0.join("linked-config.yaml"),
                "site",
                &[],
                b"credential"
            )
            .is_err()
        );
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
