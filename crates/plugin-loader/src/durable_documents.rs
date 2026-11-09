// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Guarded operator document publication, inside the existing native durable owner.
use std::{io, path::Path};
use zeroize::Zeroizing;

pub enum DocumentInspection {
    Original {
        metadata: Zeroizing<Vec<u8>>,
        read_only: bool,
    },
    Converted,
    Missing,
    Changed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentReplace {
    Published,
    AlreadyConverted,
    ReadOnly,
    Missing,
    Changed,
}

pub fn inspect_document(
    path: &Path,
    original: &[u8],
    converted: &[u8],
) -> io::Result<DocumentInspection> {
    platform::inspect(path, original, converted)
}
pub fn replace_document(
    path: &Path,
    original: &[u8],
    converted: &[u8],
    metadata: &[u8],
) -> io::Result<DocumentReplace> {
    platform::replace(path, Some(original), converted, metadata)
}
pub fn recover_document(
    path: &Path,
    converted: &[u8],
    metadata: &[u8],
) -> io::Result<DocumentReplace> {
    platform::replace(path, None, converted, metadata)
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid document publication metadata",
    )
}
fn append(out: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    let n = u32::try_from(bytes.len()).map_err(|_| invalid())?;
    out.try_reserve(4 + bytes.len())
        .map_err(|_| io::Error::other("document metadata allocation failed"))?;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    let value = input.get(..n).ok_or_else(invalid)?;
    *input = &input[n..];
    Ok(value)
}
fn field<'a>(input: &mut &'a [u8]) -> io::Result<&'a [u8]> {
    let n = u32::from_le_bytes(take(input, 4)?.try_into().map_err(|_| invalid())?) as usize;
    take(input, n)
}
fn bounded_read(file: &mut std::fs::File, max: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::io::{Read, Seek};
    file.rewind()?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use crate::migration_secrets::unix::{name, open_at, parent_directory};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::{
        ffi::{CStr, CString},
        fs::{File, Metadata},
        io::Write,
        os::fd::AsRawFd,
    };

    fn parent(path: &Path) -> io::Result<(std::path::PathBuf, File)> {
        parent_directory(path).map_err(io::Error::other)
    }
    fn filename(path: &Path) -> io::Result<CString> {
        name(path.file_name().ok_or_else(invalid)?).map_err(io::Error::other)
    }
    fn source(dir: &File, file: &CStr) -> io::Result<File> {
        let f = open_at(dir, file, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        if !f.metadata()?.is_file() {
            return Err(invalid());
        }
        Ok(f)
    }
    fn same_parent(dir: &File, saved: &[u8]) -> io::Result<bool> {
        let m = dir.metadata()?;
        Ok(saved.get(..16)
            == Some(
                [m.dev().to_le_bytes(), m.ino().to_le_bytes()]
                    .concat()
                    .as_slice(),
            ))
    }
    fn security(file: &File) -> io::Result<Zeroizing<Vec<u8>>> {
        let m = file.metadata()?;
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&m.uid().to_le_bytes());
        out.extend_from_slice(&m.gid().to_le_bytes());
        out.extend_from_slice(&(m.mode() & 0o7777).to_le_bytes());
        #[cfg(target_os = "macos")]
        {
            append(&mut out, &mac_acl::get(file)?)?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            append(&mut out, &[])?;
        }
        for (key, value) in xattrs::get(file)? {
            append(&mut out, &key)?;
            append(&mut out, &value)?;
        }
        Ok(out)
    }
    fn metadata(dir: &File, file: &File) -> io::Result<Zeroizing<Vec<u8>>> {
        let m = dir.metadata()?;
        let mut out = Zeroizing::new(vec![1]);
        out.extend_from_slice(&m.dev().to_le_bytes());
        out.extend_from_slice(&m.ino().to_le_bytes());
        out.extend_from_slice(&security(file)?);
        Ok(out)
    }
    fn restore(file: &File, bytes: &[u8]) -> io::Result<()> {
        let mut bytes = bytes;
        let uid = u32::from_le_bytes(take(&mut bytes, 4)?.try_into().map_err(|_| invalid())?);
        let gid = u32::from_le_bytes(take(&mut bytes, 4)?.try_into().map_err(|_| invalid())?);
        let mode = u32::from_le_bytes(take(&mut bytes, 4)?.try_into().map_err(|_| invalid())?);
        // SAFETY: the fresh temporary file descriptor is live; uid/gid come from its source checkpoint.
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        let acl = field(&mut bytes)?;
        #[cfg(target_os = "macos")]
        {
            mac_acl::set(file, acl)?;
        }
        #[cfg(not(target_os = "macos"))]
        if !acl.is_empty() {
            return Err(invalid());
        }
        while !bytes.is_empty() {
            let key = field(&mut bytes)?;
            let value = field(&mut bytes)?;
            xattrs::set(file, key, value)?;
        }
        Ok(())
    }
    pub(super) fn inspect(
        path: &Path,
        original: &[u8],
        converted: &[u8],
    ) -> io::Result<DocumentInspection> {
        let (absolute, dir) = parent(path)?;
        let mut f = match source(&dir, &filename(&absolute)?) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(DocumentInspection::Missing);
            }
            Err(e) => return Err(e),
        };
        let bytes = bounded_read(&mut f, original.len().max(converted.len()))?;
        if bytes.as_slice() == converted {
            return Ok(DocumentInspection::Converted);
        }
        if bytes.as_slice() != original {
            return Ok(DocumentInspection::Changed);
        }
        Ok(DocumentInspection::Original {
            metadata: metadata(&dir, &f)?,
            read_only: f.metadata()?.permissions().readonly(),
        })
    }
    struct Temporary<'a> {
        dir: &'a File,
        name: CString,
    }
    impl Drop for Temporary<'_> {
        fn drop(&mut self) {
            // SAFETY: this name was created exclusively under the pinned directory and remains valid.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
    fn identity(m: &Metadata) -> (u64, u64) {
        (m.dev(), m.ino())
    }
    pub(super) fn replace(
        path: &Path,
        original: Option<&[u8]>,
        converted: &[u8],
        saved: &[u8],
    ) -> io::Result<DocumentReplace> {
        let saved = saved.strip_prefix(&[1]).ok_or_else(invalid)?;
        if saved.len() < 28 {
            return Err(invalid());
        }
        let (absolute, dir) = parent(path)?;
        if !same_parent(&dir, saved)? {
            return Ok(DocumentReplace::Changed);
        }
        let final_name = filename(&absolute)?;
        let mut prior = match source(&dir, &final_name) {
            Ok(mut f) => {
                let bytes = bounded_read(
                    &mut f,
                    original.map_or(converted.len(), |b| b.len().max(converted.len())),
                )?;
                if bytes.as_slice() == converted {
                    f.sync_all()?;
                    dir.sync_all()?;
                    return Ok(DocumentReplace::AlreadyConverted);
                }
                if !original.is_some_and(|v| v == bytes.as_slice()) {
                    return Ok(DocumentReplace::Changed);
                }
                if f.metadata()?.permissions().readonly() {
                    return Ok(DocumentReplace::ReadOnly);
                }
                if security(&f)?.as_slice() != &saved[16..] {
                    return Ok(DocumentReplace::Changed);
                }
                match f.try_lock() {
                    Ok(()) => {}
                    Err(std::fs::TryLockError::WouldBlock) => return Ok(DocumentReplace::ReadOnly),
                    Err(std::fs::TryLockError::Error(e)) => return Err(e),
                }
                Some(f)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && original.is_none() => None,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DocumentReplace::Missing),
            Err(e) => return Err(e),
        };
        let mut random = [0; 16];
        getrandom::fill(&mut random)
            .map_err(|_| io::Error::other("document temporary entropy failed"))?;
        let temporary = Temporary {
            dir: &dir,
            name: CString::new(format!(".busbar-document-{}.tmp", hex::encode(random)))
                .map_err(|_| invalid())?,
        };
        let mut file = open_at(
            &dir,
            &temporary.name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        restore(&file, &saved[16..])?;
        if security(&file)?.as_slice() != &saved[16..] {
            return Err(invalid());
        }
        file.write_all(converted)?;
        file.flush()?;
        file.sync_all()?;
        let (_, current_parent) = parent(path)?;
        if !same_parent(&current_parent, saved)? {
            return Ok(DocumentReplace::Changed);
        }
        let mut staged = source(&dir, &temporary.name)?;
        if identity(&staged.metadata()?) != identity(&file.metadata()?)
            || bounded_read(&mut staged, converted.len())?.as_slice() != converted
        {
            return Ok(DocumentReplace::Changed);
        }
        if let Some(prior) = prior.as_mut() {
            let current = match source(&dir, &final_name) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Ok(DocumentReplace::Missing);
                }
                Err(e) => return Err(e),
            };
            if identity(&current.metadata()?) != identity(&prior.metadata()?)
                || security(prior)?.as_slice() != &saved[16..]
                || bounded_read(prior, original.expect("existing source").len())?.as_slice()
                    != original.expect("existing source")
            {
                return Ok(DocumentReplace::Changed);
            }
            // SAFETY: both names are valid and relative to this same pinned parent; rename never follows the destination.
            if unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    temporary.name.as_ptr(),
                    dir.as_raw_fd(),
                    final_name.as_ptr(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        } else {
            // SAFETY: exclusive link publication refuses any new existing destination and follows neither final entry.
            if unsafe {
                libc::linkat(
                    dir.as_raw_fd(),
                    temporary.name.as_ptr(),
                    dir.as_raw_fd(),
                    final_name.as_ptr(),
                    0,
                )
            } < 0
            {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::AlreadyExists {
                    return Ok(DocumentReplace::Changed);
                }
                return Err(e);
            }
        }
        drop(file);
        drop(temporary);
        dir.sync_all()?;
        Ok(DocumentReplace::Published)
    }

    #[cfg(target_os = "macos")]
    mod mac_acl {
        use super::*;
        unsafe extern "C" {
            fn acl_init(count: libc::c_int) -> *mut libc::c_void;
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_uint) -> *mut libc::c_void;
            fn acl_to_text(acl: *mut libc::c_void, len: *mut libc::ssize_t) -> *mut libc::c_char;
            fn acl_from_text(text: *const libc::c_char) -> *mut libc::c_void;
            fn acl_set_fd_np(
                fd: libc::c_int,
                acl: *mut libc::c_void,
                kind: libc::c_uint,
            ) -> libc::c_int;
            fn acl_free(value: *mut libc::c_void) -> libc::c_int;
        }
        struct Owned(*mut libc::c_void);
        impl Drop for Owned {
            fn drop(&mut self) {
                // SAFETY: each Owned holds one native allocation from the ACL API.
                unsafe {
                    acl_free(self.0);
                }
            }
        }
        pub(super) fn get(file: &File) -> io::Result<Vec<u8>> {
            // SAFETY: the file descriptor is live; ACL_TYPE_EXTENDED is from the platform header.
            let acl = Owned(unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) });
            if acl.0.is_null() {
                let error = io::Error::last_os_error();
                // macOS reports ENOENT for an existing regular file with no extended ACL.
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(Vec::new());
                }
                return Err(error);
            }
            let mut len = 0;
            // SAFETY: ACL is valid and len is writable for this call.
            let text = Owned(unsafe { acl_to_text(acl.0, &mut len) }.cast());
            if text.0.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: acl_to_text returns a valid NUL-terminated allocated text until Owned drops.
            Ok(unsafe { CStr::from_ptr(text.0.cast()) }.to_bytes().to_vec())
        }
        pub(super) fn set(file: &File, bytes: &[u8]) -> io::Result<()> {
            let text = CString::new(bytes).map_err(|_| invalid())?;
            // SAFETY: an empty ACL is explicitly initialized; otherwise the terminated text
            // is parsed by the native ACL parser. Both return independently owned ACLs.
            let acl = Owned(unsafe {
                if bytes.is_empty() {
                    acl_init(0)
                } else {
                    acl_from_text(text.as_ptr())
                }
            });
            if acl.0.is_null() {
                return Err(invalid());
            }
            // SAFETY: ACL and live file descriptor remain valid throughout this call.
            if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, 0x100) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    mod xattrs {
        use super::*;
        pub(super) fn get(file: &File) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
            #[cfg(target_os = "linux")]
            {
                // SAFETY: null with zero size queries the required list buffer size.
                let n = unsafe { libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut names = vec![0; n as usize];
                // SAFETY: names owns exactly its supplied buffer length.
                let n = unsafe {
                    libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len())
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                names.truncate(n as usize);
                let mut out = Vec::new();
                for key in names.split(|b| *b == 0).filter(|key| {
                    key.starts_with(b"security.") || key.starts_with(b"system.posix_acl_")
                }) {
                    let name = CString::new(key).map_err(|_| invalid())?;
                    // SAFETY: native name and file descriptor are valid; zero queries size.
                    let n = unsafe {
                        libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0)
                    };
                    if n < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let mut value = vec![0; n as usize];
                    // SAFETY: value owns its entire writable buffer and name is terminated.
                    let n = unsafe {
                        libc::fgetxattr(
                            file.as_raw_fd(),
                            name.as_ptr(),
                            value.as_mut_ptr().cast(),
                            value.len(),
                        )
                    };
                    if n < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    value.truncate(n as usize);
                    out.push((key.to_vec(), value));
                }
                out.sort();
                Ok(out)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = file;
                Ok(Vec::new())
            }
        }
        pub(super) fn set(file: &File, key: &[u8], value: &[u8]) -> io::Result<()> {
            #[cfg(target_os = "linux")]
            {
                let key = CString::new(key).map_err(|_| invalid())?;
                // SAFETY: key and value buffers live through this call; descriptor is our fresh temporary.
                if unsafe {
                    libc::fsetxattr(
                        file.as_raw_fd(),
                        key.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (file, key, value);
                Err(invalid())
            }
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        os::windows::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Component, PathBuf, Prefix},
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{
            Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
            GetKernelObjectSecurity, GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION,
            GROUP_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, SE_SACL_PRESENT,
            UNPROTECTED_DACL_SECURITY_INFORMATION,
        },
        Storage::FileSystem::{
            FileRenameInfoEx, GetFileInformationByHandle, SetFileInformationByHandle,
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
            FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
    };
    fn handle(file: &File) -> HANDLE {
        file.as_raw_handle() as HANDLE
    }
    fn stage(name: &str, error: io::Error) -> io::Error {
        io::Error::new(
            error.kind(),
            format!("document publication {name}: {error}"),
        )
    }
    pub(super) fn parents(path: &Path) -> io::Result<(PathBuf, Vec<File>)> {
        let absolute = std::path::absolute(path)?;
        if absolute.components().any(|part| matches!(part, Component::Prefix(prefix) if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_,_) | Prefix::VerbatimUNC(_,_)))) {
            return Err(invalid());
        }
        if absolute
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(invalid());
        }
        let mut current = PathBuf::new();
        let mut held = Vec::new();
        for component in absolute.parent().ok_or_else(invalid)?.components() {
            current.push(component.as_os_str());
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&current)?;
            let metadata = file.metadata()?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(invalid());
            }
            held.push(file);
        }
        if held.is_empty() {
            return Err(invalid());
        }
        Ok((absolute, held))
    }
    fn source(path: &Path) -> io::Result<File> {
        source_shared(path, FILE_SHARE_READ | FILE_SHARE_DELETE)
    }
    fn source_shared(path: &Path, sharing: u32) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(sharing)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid());
        }
        Ok(file)
    }
    pub(super) fn staged_writer(path: &Path) -> io::Result<File> {
        // Keep this exact writing handle through rename and the final flush. It
        // supplies DELETE for the handle-based rename and denies every new writer.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(0x8000_0000 | 0x4000_0000 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH)
            .open(path)
    }
    pub(super) fn identity(file: &File) -> io::Result<[u8; 12]> {
        // SAFETY: the native output record permits an all-zero initial value.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: live handle and writable struct are valid throughout the native call.
        if unsafe { GetFileInformationByHandle(handle(file), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = [0; 12];
        out[..4].copy_from_slice(&info.dwVolumeSerialNumber.to_le_bytes());
        out[4..8].copy_from_slice(&info.nFileIndexHigh.to_le_bytes());
        out[8..].copy_from_slice(&info.nFileIndexLow.to_le_bytes());
        Ok(out)
    }
    pub(super) fn security(file: &File) -> io::Result<Vec<u8>> {
        let flags = OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
            | LABEL_SECURITY_INFORMATION;
        let mut needed = 0;
        // SAFETY: zero buffer queries the native self-relative descriptor length.
        unsafe {
            GetKernelObjectSecurity(handle(file), flags, std::ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = vec![0; needed as usize];
        // SAFETY: bytes owns exactly the requested native output buffer.
        if unsafe {
            GetKernelObjectSecurity(
                handle(file),
                flags,
                bytes.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        bytes.truncate(needed as usize);
        Ok(bytes)
    }
    fn metadata(parent: &File, file: &File) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(vec![2]);
        bytes.extend_from_slice(&identity(parent)?);
        bytes.extend_from_slice(&file.metadata()?.file_attributes().to_le_bytes());
        append(&mut bytes, &security(file)?)?;
        Ok(bytes)
    }
    // Validate every relative native descriptor span before passing protected stored bytes to Win32.
    fn valid_descriptor(bytes: &[u8]) -> bool {
        if bytes.len() < 20
            || bytes[0] != 1
            || u16::from_le_bytes([bytes[2], bytes[3]]) & 0x8000 == 0
        {
            return false;
        }
        for (slot, sid) in [(4, true), (8, true), (12, false), (16, false)] {
            let offset =
                u32::from_le_bytes(bytes[slot..slot + 4].try_into().expect("header length"))
                    as usize;
            if offset == 0 {
                continue;
            }
            let Some(header) = bytes.get(offset..).and_then(|tail| tail.get(..8)) else {
                return false;
            };
            let length = if sid {
                if header[0] != 1 || header[1] > 15 {
                    return false;
                }
                8 + usize::from(header[1]) * 4
            } else {
                usize::from(u16::from_le_bytes([header[2], header[3]]))
            };
            if offset < 20
                || length < 8
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > bytes.len())
            {
                return false;
            }
            if !sid {
                let mut at = offset + 8;
                for _ in 0..u16::from_le_bytes([header[4], header[5]]) {
                    let Some(ace) = bytes.get(at..).and_then(|tail| tail.get(..4)) else {
                        return false;
                    };
                    let size = usize::from(u16::from_le_bytes([ace[2], ace[3]]));
                    if size < 4 || at.checked_add(size).is_none_or(|end| end > offset + length) {
                        return false;
                    }
                    at += size;
                }
            }
        }
        true
    }
    fn restore(file: &File, saved: &[u8]) -> io::Result<()> {
        let mut input = saved;
        let descriptor = field(&mut input)?;
        if !input.is_empty() || !valid_descriptor(descriptor) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid document publication security descriptor spans",
            ));
        }
        let mut descriptor = descriptor.to_vec();
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: descriptor is the self-relative native descriptor captured into this protected checkpoint.
        if unsafe {
            GetSecurityDescriptorControl(
                descriptor.as_mut_ptr().cast(),
                &mut control,
                &mut revision,
            )
        } == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid document publication security descriptor control",
            ));
        }
        let protection = if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
        let pointer = descriptor.as_mut_ptr();
        let component = |slot: usize| {
            let offset = u32::from_le_bytes(
                descriptor[slot..slot + 4]
                    .try_into()
                    .expect("validated descriptor header"),
            ) as usize;
            if offset == 0 {
                std::ptr::null_mut()
            } else {
                // SAFETY: valid_descriptor checked every component's complete span.
                unsafe { pointer.add(offset).cast() }
            }
        };
        // Setting a null label SACL synthesizes SE_SACL_PRESENT. If the original
        // label SACL was absent, leave the same-parent temporary's label unchanged;
        // the exact readback below still refuses any differing inherited policy.
        let label = if control & SE_SACL_PRESENT != 0 {
            LABEL_SECURITY_INFORMATION
        } else {
            0
        };
        // SAFETY: the temporary file handle and every pointer into the checked
        // self-relative descriptor remain live. Use the filesystem-specific API
        // so the original DACL's automatic inheritance remains represented.
        let result = unsafe {
            SetSecurityInfo(
                handle(file),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | label
                    | protection,
                component(4),
                component(8),
                component(16).cast(),
                component(12).cast(),
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        Ok(())
    }
    fn rename(file: &File, destination: &Path, replace: bool) -> io::Result<()> {
        let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
        if name.is_empty() || name.contains(&0) || !destination.is_absolute() {
            return Err(invalid());
        }
        let name_bytes = name.len().checked_mul(2).ok_or_else(invalid)?;
        let length = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
            .checked_add(name_bytes)
            .ok_or_else(invalid)?
            .max(std::mem::size_of::<FILE_RENAME_INFO>());
        let length_u32 = u32::try_from(length).map_err(|_| invalid())?;
        // usize storage gives FILE_RENAME_INFO its native pointer alignment. The
        // filename offset comes from windows-sys, including platform ABI padding.
        let mut storage = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        // SAFETY: aligned initialized storage spans the complete native header and
        // UTF-16 name. Native pointers are retained for the whole synchronous call.
        unsafe {
            // FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS lets the
            // original's deny-write/byte-lock handles remain live during replacement.
            (*info).Anonymous.Flags = if replace {
                0x0000_0001 | 0x0000_0002
            } else {
                0
            };
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = u32::try_from(name_bytes).map_err(|_| invalid())?;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
                name.len(),
            );
            if SetFileInformationByHandle(handle(file), FileRenameInfoEx, info.cast(), length_u32)
                == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    pub(super) fn inspect(
        path: &Path,
        original: &[u8],
        converted: &[u8],
    ) -> io::Result<DocumentInspection> {
        let (absolute, parents) = parents(path)?;
        let mut file = match source(&absolute) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(DocumentInspection::Missing);
            }
            Err(e) => return Err(e),
        };
        let bytes = bounded_read(&mut file, original.len().max(converted.len()))?;
        if bytes.as_slice() == converted {
            return Ok(DocumentInspection::Converted);
        }
        if bytes.as_slice() != original {
            return Ok(DocumentInspection::Changed);
        }
        Ok(DocumentInspection::Original {
            metadata: metadata(parents.last().expect("parent pinned"), &file)?,
            read_only: file.metadata()?.permissions().readonly(),
        })
    }
    struct Temporary(PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    pub(super) fn replace(
        path: &Path,
        original: Option<&[u8]>,
        converted: &[u8],
        saved: &[u8],
    ) -> io::Result<DocumentReplace> {
        let saved = saved.strip_prefix(&[2]).ok_or_else(invalid)?;
        if saved.len() < 16 {
            return Err(invalid());
        }
        let (absolute, parents) = parents(path)?;
        let parent = parents.last().expect("pinned parent");
        if identity(parent)?.as_slice() != &saved[..12] {
            return Ok(DocumentReplace::Changed);
        }
        let mut input = &saved[16..];
        let security_saved = field(&mut input)?;
        if !input.is_empty() {
            return Err(invalid());
        }
        let mut expected = converted;
        let mut prior = match source(&absolute) {
            Ok(mut file) => {
                // Check operator exclusion before reading through a different handle's
                // byte-range lock, which Windows would reject as a read I/O failure.
                match file.try_lock() {
                    Ok(()) => {}
                    Err(std::fs::TryLockError::WouldBlock) => return Ok(DocumentReplace::ReadOnly),
                    Err(std::fs::TryLockError::Error(e)) => return Err(e),
                }
                let bytes = bounded_read(
                    &mut file,
                    original.map_or(converted.len(), |b| b.len().max(converted.len())),
                )?;
                if bytes.as_slice() == converted {
                    // A previous failed/unknown barrier is resolved by another exact write-through
                    // replacement, rather than assuming visible bytes prove namespace durability.
                    expected = converted;
                } else if original.is_some_and(|v| v == bytes.as_slice()) {
                    expected = original.expect("matched original source");
                } else {
                    return Ok(DocumentReplace::Changed);
                }
                if file.metadata()?.permissions().readonly() {
                    return Ok(DocumentReplace::ReadOnly);
                }
                let saved_attributes =
                    u32::from_le_bytes(saved[12..16].try_into().map_err(|_| invalid())?);
                if (file.metadata()?.file_attributes() ^ saved_attributes)
                    & FILE_ATTRIBUTE_ENCRYPTED
                    != 0
                    || security(&file)?.as_slice() != security_saved
                {
                    return Ok(DocumentReplace::Changed);
                }
                Some(file)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound && original.is_none() => None,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DocumentReplace::Missing),
            Err(e) => return Err(e),
        };
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| io::Error::other("document entropy failed"))?;
        let temporary = Temporary(
            absolute
                .parent()
                .ok_or_else(invalid)?
                .join(format!(".busbar-document-{}.tmp", hex::encode(random))),
        );
        let mut file = staged_writer(&temporary.0)?;
        restore(&file, &saved[16..])?;
        let restored = security(&file)?;
        if restored.as_slice() != security_saved {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "document publication security readback differs (saved length {}, control {:04x}; restored length {}, control {:04x})",
                    security_saved.len(),
                    u16::from_le_bytes(security_saved[2..4].try_into().map_err(|_| invalid())?),
                    restored.len(),
                    u16::from_le_bytes(restored[2..4].try_into().map_err(|_| invalid())?),
                ),
            ));
        }
        let original_attributes =
            u32::from_le_bytes(saved[12..16].try_into().map_err(|_| invalid())?);
        if original_attributes & FILE_ATTRIBUTE_ENCRYPTED != 0 {
            // EFS recipient/key metadata is not a DACL. A differently encrypted temporary
            // cannot prove the original owner's access; keep this specific source in memory.
            return Ok(DocumentReplace::ReadOnly);
        }
        file.write_all(converted)?;
        file.flush()?;
        file.sync_all()?;
        let temporary_id = identity(&file)?;
        // Readback shares WRITE only to coexist with our retained writer. That
        // original handle's sharing still refuses every new writing handle.
        let readback_sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let mut staged = source_shared(&temporary.0, readback_sharing)?;
        if identity(&staged)? != temporary_id
            || bounded_read(&mut staged, converted.len())?.as_slice() != converted
            || security(&staged)?.as_slice() != security_saved
        {
            return Ok(DocumentReplace::Changed);
        }
        if let Some(prior) = prior.as_mut() {
            let current = source(&absolute).map_err(|error| stage("original reopen", error))?;
            if identity(&current)? != identity(prior)?
                || security(prior)?.as_slice() != security_saved
                || bounded_read(prior, expected.len())
                    .map_err(|error| stage("locked original readback", error))?
                    .as_slice()
                    != expected
            {
                return Ok(DocumentReplace::Changed);
            }
        }
        let current_temporary = source_shared(&temporary.0, readback_sharing)?;
        if identity(&current_temporary)? != temporary_id
            || temporary_id[..4] != identity(parent)?[..4]
        {
            return Ok(DocumentReplace::Changed);
        }
        // All ancestors, the exact staged writer and the locked original remain
        // pinned. This same-volume native rename has no copy or namespace-gap fallback.
        // FILE_FLAG_WRITE_THROUGH also flushes rename metadata; explicitly flush
        // the same retained writing handle before and after the namespace crossing.
        if let Err(error) = rename(&file, &absolute, prior.is_some()) {
            if original.is_none() && error.kind() == io::ErrorKind::AlreadyExists {
                return Ok(DocumentReplace::Changed);
            }
            return Err(stage("native write-through handle rename", error));
        }
        file.sync_all()
            .map_err(|error| stage("published handle sync", error))?;
        let mut published = source_shared(&absolute, readback_sharing)
            .map_err(|error| stage("published reopen", error))?;
        if identity(&published)? != temporary_id
            || bounded_read(&mut published, converted.len())?.as_slice() != converted
            || security(&published)?.as_slice() != security_saved
        {
            return Ok(DocumentReplace::Changed);
        }
        drop(temporary);
        Ok(DocumentReplace::Published)
    }
}

/// Safe native handle primitives shared with the existing private artifact owner.
#[cfg(windows)]
pub(crate) fn windows_parent(path: &Path) -> io::Result<(std::path::PathBuf, Vec<std::fs::File>)> {
    platform::parents(path)
}
#[cfg(windows)]
pub(crate) fn windows_security(file: &std::fs::File) -> io::Result<Vec<u8>> {
    platform::security(file)
}
#[cfg(windows)]
pub(crate) fn windows_identity(file: &std::fs::File) -> io::Result<[u8; 12]> {
    platform::identity(file)
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    pub(super) fn inspect(_: &Path, _: &[u8], _: &[u8]) -> io::Result<DocumentInspection> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native document owner unavailable",
        ))
    }
    pub(super) fn replace(
        _: &Path,
        _: Option<&[u8]>,
        _: &[u8],
        _: &[u8],
    ) -> io::Result<DocumentReplace> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native document owner unavailable",
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().canonicalize().unwrap();
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = base.join(format!("document-commit-{}", hex::encode(random)));
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("config.yaml"), b"original").unwrap();
            std::fs::set_permissions(
                path.join("config.yaml"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("config.yaml")
        }
        fn capture(&self) -> Zeroizing<Vec<u8>> {
            match inspect_document(&self.path(), b"original", b"converted").unwrap() {
                DocumentInspection::Original {
                    metadata,
                    read_only: false,
                } => metadata,
                _ => panic!("original writable fixture"),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn publication_preserves_owner_group_permissions_and_is_idempotent() {
        let f = Fixture::new();
        let before = std::fs::metadata(f.path()).unwrap();
        let saved = f.capture();
        assert_eq!(
            replace_document(&f.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::Published
        );
        let after = std::fs::metadata(f.path()).unwrap();
        assert_eq!(
            (before.uid(), before.gid(), before.mode() & 0o7777),
            (after.uid(), after.gid(), after.mode() & 0o7777)
        );
        assert_eq!(std::fs::read(f.path()).unwrap(), b"converted");
        assert_eq!(std::fs::read_dir(&f.0).unwrap().count(), 1);
        assert_eq!(
            replace_document(&f.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::AlreadyConverted
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn a_nonempty_native_acl_is_preserved_with_the_file_owner() {
        let fixture = Fixture::new();
        assert!(std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(fixture.path())
            .status()
            .unwrap()
            .success());
        let saved = fixture.capture();
        assert_eq!(
            replace_document(&fixture.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::Published
        );
        let DocumentInspection::Original { metadata, .. } =
            inspect_document(&fixture.path(), b"converted", b"unused").unwrap()
        else {
            panic!("published regular file");
        };
        assert_eq!(
            metadata.as_slice(),
            saved.as_slice(),
            "native ACL, owner, group and mode survive replacement"
        );
    }
    #[test]
    fn third_party_edit_and_permission_change_are_not_overwritten() {
        let f = Fixture::new();
        let saved = f.capture();
        std::fs::write(f.path(), b"edited").unwrap();
        assert_eq!(
            replace_document(&f.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::Changed
        );
        assert_eq!(std::fs::read(f.path()).unwrap(), b"edited");
        std::fs::write(f.path(), b"original").unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            replace_document(&f.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::ReadOnly
        );
        assert_eq!(std::fs::read(f.path()).unwrap(), b"original");
    }
    #[test]
    fn symlink_source_and_parent_are_refused_without_touching_the_target() {
        let f = Fixture::new();
        let other = Fixture::new();
        let saved = f.capture();
        std::fs::remove_file(f.path()).unwrap();
        symlink(other.path(), f.path()).unwrap();
        assert!(replace_document(&f.path(), b"original", b"converted", &saved).is_err());
        assert_eq!(std::fs::read(other.path()).unwrap(), b"original");
        symlink(&other.0, f.0.join("linked")).unwrap();
        assert!(replace_document(
            &f.0.join("linked/config.yaml"),
            b"original",
            b"converted",
            &saved
        )
        .is_err());
    }
    #[test]
    fn missing_requires_explicit_recovery_and_the_original_parent_and_security() {
        let f = Fixture::new();
        let other = Fixture::new();
        let saved = f.capture();
        std::fs::remove_file(f.path()).unwrap();
        assert_eq!(
            replace_document(&f.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::Missing
        );
        assert_eq!(
            recover_document(&other.path(), b"converted", &saved).unwrap(),
            DocumentReplace::Changed
        );
        assert_eq!(
            recover_document(&f.path(), b"converted", &saved).unwrap(),
            DocumentReplace::Published
        );
        assert_eq!(std::fs::metadata(f.path()).unwrap().mode() & 0o7777, 0o640);
        std::fs::write(f.path(), b"third party").unwrap();
        assert_eq!(
            recover_document(&f.path(), b"converted", &saved).unwrap(),
            DocumentReplace::Changed
        );
    }
    #[test]
    fn an_existing_operator_lock_leaves_the_source_unchanged() {
        let f = Fixture::new();
        let saved = f.capture();
        let locked = std::fs::File::open(f.path()).unwrap();
        locked.lock().unwrap();
        assert_eq!(
            replace_document(&f.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::ReadOnly
        );
        assert_eq!(std::fs::read(f.path()).unwrap(), b"original");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::{fs::File, path::PathBuf};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let directory = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("busbar-windows-document-{}", hex::encode(random)));
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("config.yaml"), b"original").unwrap();
            Self(directory)
        }
        fn path(&self) -> PathBuf {
            self.0.join("config.yaml")
        }
        fn capture(&self) -> Zeroizing<Vec<u8>> {
            match inspect_document(&self.path(), b"original", b"converted").unwrap() {
                DocumentInspection::Original { metadata, .. } => metadata,
                _ => panic!("expected original Windows document"),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn publication_preserves_native_security_and_retry_reestablishes_barrier() {
        let fixture = Fixture::new();
        let saved = fixture.capture();
        let before = windows_security(&File::open(fixture.path()).unwrap()).unwrap();
        for _ in 0..2 {
            assert_eq!(
                replace_document(&fixture.path(), b"original", b"converted", &saved).unwrap(),
                DocumentReplace::Published
            );
            assert_eq!(std::fs::read(fixture.path()).unwrap(), b"converted");
            assert_eq!(
                windows_security(&File::open(fixture.path()).unwrap()).unwrap(),
                before
            );
            assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
        }
    }

    #[test]
    fn edited_source_and_wrong_parent_recovery_are_refused() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let saved = fixture.capture();
        std::fs::write(fixture.path(), b"operator edit").unwrap();
        assert_eq!(
            replace_document(&fixture.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::Changed
        );
        assert_eq!(std::fs::read(fixture.path()).unwrap(), b"operator edit");
        assert_eq!(
            recover_document(&other.path(), b"converted", &saved).unwrap(),
            DocumentReplace::Changed
        );
    }

    #[test]
    fn missing_source_requires_explicit_exclusive_recovery() {
        let fixture = Fixture::new();
        let saved = fixture.capture();
        std::fs::remove_file(fixture.path()).unwrap();
        assert_eq!(
            replace_document(&fixture.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::Missing
        );
        assert_eq!(
            recover_document(&fixture.path(), b"converted", &saved).unwrap(),
            DocumentReplace::Published
        );
        assert_eq!(std::fs::read(fixture.path()).unwrap(), b"converted");
        std::fs::write(fixture.path(), b"new occupant").unwrap();
        assert_eq!(
            recover_document(&fixture.path(), b"converted", &saved).unwrap(),
            DocumentReplace::Changed
        );
    }

    #[test]
    fn ordinary_replacement_keeps_the_only_bootstrap_path_present() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        };
        let fixture = Fixture::new();
        let saved = fixture.capture();
        let path = fixture.path();
        let running = Arc::new(AtomicBool::new(true));
        let observe = running.clone();
        let (ready, started) = mpsc::channel();
        let observer = std::thread::spawn(move || {
            std::fs::metadata(&path).unwrap();
            ready.send(()).unwrap();
            let mut samples = 0usize;
            while observe.load(Ordering::Acquire) {
                // Opening content can legitimately encounter the operator file lock; a
                // namespace lookup must continue finding the single bootstrap document.
                std::fs::metadata(&path).expect("bootstrap pathname disappeared during rename");
                samples += 1;
            }
            samples
        });
        started.recv().unwrap();
        let result = (|| {
            for _ in 0..16 {
                assert_eq!(
                    replace_document(&fixture.path(), b"original", b"converted", &saved)?,
                    DocumentReplace::Published
                );
            }
            io::Result::Ok(())
        })();
        running.store(false, Ordering::Release);
        let samples = observer.join().unwrap();
        result.unwrap();
        assert!(samples > 0);
        assert_eq!(std::fs::read(fixture.path()).unwrap(), b"converted");
    }

    #[test]
    fn junction_parent_is_refused_without_touching_the_target() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let saved = other.capture();
        let junction = fixture.0.join("linked-parent");
        // Directory junction creation is available to ordinary Windows users and
        // exercises a native reparse point without requiring symlink privilege.
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&other.0)
            .output()
            .unwrap();
        assert!(output.status.success(), "native junction creation failed");
        let result = replace_document(
            &junction.join("config.yaml"),
            b"original",
            b"converted",
            &saved,
        );
        std::fs::remove_dir(&junction).unwrap();
        assert!(result.is_err());
        assert_eq!(std::fs::read(other.path()).unwrap(), b"original");
    }

    #[test]
    fn an_existing_operator_lock_preserves_the_original_document() {
        let fixture = Fixture::new();
        let saved = fixture.capture();
        let held = File::open(fixture.path()).unwrap();
        held.lock().unwrap();
        assert_eq!(
            replace_document(&fixture.path(), b"original", b"converted", &saved).unwrap(),
            DocumentReplace::ReadOnly
        );
        held.unlock().unwrap();
        assert_eq!(std::fs::read(fixture.path()).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn retained_staged_writer_denies_new_writers_even_with_shared_readback() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        let fixture = Fixture::new();
        let path = fixture.0.join("staged.yaml");
        let held = platform::staged_writer(&path).unwrap();
        let readback = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        let denied = std::fs::OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .expect_err("the retained staged writer must deny new writers");
        assert_eq!(denied.raw_os_error(), Some(32), "native sharing violation");
        drop(held);
        let admitted = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        drop(admitted);
        drop(readback);
    }
}
