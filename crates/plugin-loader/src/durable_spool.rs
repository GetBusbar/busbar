// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Transient encrypted source custody. Nothing here is durable application state:
//! the random key exists only in memory, and the backing file is unnamed on Unix
//! or delete-on-close on Windows. Restart reconstructs the source from its owner.

use busbar_contract::abi::sdk::aead::{AesGcm, AES_256_KEY_LEN, GCM_NONCE_LEN, GCM_TAG_LEN};
use std::{
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};
use zeroize::{Zeroize, Zeroizing};

const BLOCK: usize = 64 * 1024;
const USED: usize = 4;
const PLAIN: usize = USED + BLOCK;
const FRAME: usize = GCM_NONCE_LEN + PLAIN + GCM_TAG_LEN;
const FORMAT: u32 = 1;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "encrypted source spool is invalid",
    )
}
fn exhausted() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "encrypted source spool offset exhausted",
    )
}
fn failed() -> io::Error {
    io::Error::other("encrypted source spool is unavailable")
}
fn allocated(length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| failed())?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn offset(index: u64) -> io::Result<u64> {
    index.checked_mul(FRAME as u64).ok_or_else(exhausted)
}
fn aad(identity: &[u8; 16], index: u64) -> [u8; 52] {
    let mut bytes = [0; 52];
    bytes[..16].copy_from_slice(b"busbar.spool.v1\0");
    bytes[16..32].copy_from_slice(identity);
    bytes[32..40].copy_from_slice(&index.to_be_bytes());
    bytes[40..44].copy_from_slice(&FORMAT.to_be_bytes());
    bytes[44..48].copy_from_slice(&(BLOCK as u32).to_be_bytes());
    bytes[48..52].copy_from_slice(&(PLAIN as u32).to_be_bytes());
    bytes
}

/// Append-only logical source writer with one fixed 64-KiB protected payload
/// buffer. Flush encrypts the current partial block with a fresh nonce; later
/// writes append to that block. Earlier full blocks are never rewritten.
pub struct SpoolWriter {
    file: File,
    cipher: AesGcm,
    identity: [u8; 16],
    plain: Zeroizing<Vec<u8>>,
    encoded: Vec<u8>,
    length: u64,
    index: u64,
    used: usize,
    next_nonce: u64,
    dirty: bool,
    poisoned: bool,
}
impl fmt::Debug for SpoolWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpoolWriter").finish_non_exhaustive()
    }
}
impl SpoolWriter {
    /// Create private, process-local encrypted custody under the native temporary
    /// directory. No caller supplies a file path or persistent encryption key.
    pub fn new() -> io::Result<Self> {
        let mut seed = Zeroizing::new([0u8; AES_256_KEY_LEN]);
        getrandom::fill(seed.as_mut()).map_err(|_| failed())?;
        let cipher = AesGcm::new(seed.as_ref()).map_err(|_| failed())?;
        drop(seed);
        let mut identity = [0u8; 16];
        getrandom::fill(&mut identity).map_err(|_| failed())?;
        let plain = Zeroizing::new(allocated(PLAIN)?);
        let encoded = allocated(FRAME)?;
        let file = platform::create()?;
        Ok(Self {
            file,
            cipher,
            identity,
            plain,
            encoded,
            length: 0,
            index: 0,
            used: 0,
            next_nonce: 0,
            dirty: false,
            poisoned: false,
        })
    }
    fn live(&self) -> io::Result<()> {
        if self.poisoned {
            Err(failed())
        } else {
            Ok(())
        }
    }
    fn persist(&mut self) -> io::Result<()> {
        self.live()?;
        if !self.dirty {
            return Ok(());
        }
        // Any failed encryption or partial native write permanently retires this
        // writer, so neither its nonce nor a partially written frame is reused.
        self.poisoned = true;
        let answer = (|| {
            let at = offset(self.index)?;
            self.index
                .checked_add(1)
                .and_then(|count| offset(count).ok())
                .ok_or_else(exhausted)?;
            let counter = self.next_nonce;
            self.next_nonce = counter.checked_add(1).ok_or_else(exhausted)?;
            let mut nonce = [0u8; GCM_NONCE_LEN];
            nonce[4..].copy_from_slice(&counter.to_be_bytes());
            self.plain[..USED].copy_from_slice(&(self.used as u32).to_le_bytes());
            self.plain[USED + self.used..].zeroize();
            self.encoded[..GCM_NONCE_LEN].copy_from_slice(&nonce);
            let size = self
                .cipher
                .seal(
                    &nonce,
                    &aad(&self.identity, self.index),
                    &self.plain,
                    &mut self.encoded[GCM_NONCE_LEN..],
                )
                .map_err(|_| failed())?;
            if size != PLAIN + GCM_TAG_LEN {
                return Err(failed());
            }
            self.file.seek(SeekFrom::Start(at))?;
            self.file.write_all(&self.encoded)?;
            Ok(())
        })();
        if answer.is_ok() {
            self.poisoned = false;
            self.dirty = false;
        } else {
            self.plain.as_mut_slice().zeroize();
        }
        answer
    }
    /// Seal the total logical length and block count, transferring the ephemeral
    /// key into the seekable reader. Failure publishes no readable spool.
    pub fn finish(mut self) -> io::Result<SpoolReader> {
        self.flush()?;
        let blocks = self.length.div_ceil(BLOCK as u64);
        if self.file.metadata()?.len() != offset(blocks)? {
            return Err(invalid());
        }
        self.plain.as_mut_slice().zeroize();
        Ok(SpoolReader {
            file: self.file,
            cipher: self.cipher,
            identity: self.identity,
            plain: self.plain,
            encoded: self.encoded,
            length: self.length,
            blocks,
            position: 0,
            cached: None,
            poisoned: false,
        })
    }
}
impl Write for SpoolWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.live()?;
        if input.is_empty() {
            return Ok(0);
        }
        if self.used == BLOCK {
            self.persist()?;
            self.index = self.index.checked_add(1).ok_or_else(exhausted)?;
            self.used = 0;
            self.plain.as_mut_slice().zeroize();
        }
        let count = input.len().min(BLOCK - self.used);
        let length = self
            .length
            .checked_add(count as u64)
            .ok_or_else(exhausted)?;
        self.plain[USED + self.used..USED + self.used + count].copy_from_slice(&input[..count]);
        self.used += count;
        self.length = length;
        self.dirty = true;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.persist()?;
        if let Err(error) = self.file.flush() {
            self.poisoned = true;
            self.plain.as_mut_slice().zeroize();
            return Err(error);
        }
        Ok(())
    }
}

/// Immutable authenticated logical source with one wiping block cache and O(1)
/// physical addressing. It owns the process-local key and anonymous file.
pub struct SpoolReader {
    file: File,
    cipher: AesGcm,
    identity: [u8; 16],
    plain: Zeroizing<Vec<u8>>,
    encoded: Vec<u8>,
    length: u64,
    blocks: u64,
    position: u64,
    cached: Option<u64>,
    poisoned: bool,
}
impl fmt::Debug for SpoolReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpoolReader").finish_non_exhaustive()
    }
}
impl SpoolReader {
    fn validate_size(&self) -> io::Result<()> {
        if self.poisoned {
            return Err(failed());
        }
        if self.file.metadata()?.len() != offset(self.blocks)? {
            return Err(invalid());
        }
        Ok(())
    }
    fn load(&mut self, index: u64) -> io::Result<()> {
        self.validate_size()?;
        if self.cached == Some(index) {
            return Ok(());
        }
        self.cached = None;
        self.plain.as_mut_slice().zeroize();
        if index >= self.blocks {
            return Err(invalid());
        }
        self.file.seek(SeekFrom::Start(offset(index)?))?;
        self.file.read_exact(&mut self.encoded)?;
        let nonce: [u8; GCM_NONCE_LEN] = self.encoded[..GCM_NONCE_LEN]
            .try_into()
            .map_err(|_| invalid())?;
        if nonce[..4] != [0; 4] {
            return Err(invalid());
        }
        let opened = self
            .cipher
            .open(
                &nonce,
                &aad(&self.identity, index),
                &self.encoded[GCM_NONCE_LEN..],
                &mut self.plain,
            )
            .map_err(|_| invalid())?;
        if opened != PLAIN {
            return Err(invalid());
        }
        let used = u32::from_le_bytes(self.plain[..USED].try_into().map_err(|_| invalid())?) as u64;
        let expected = if index.checked_add(1).ok_or_else(invalid)? == self.blocks {
            self.length
                .checked_sub(index.checked_mul(BLOCK as u64).ok_or_else(invalid)?)
                .ok_or_else(invalid)?
        } else {
            BLOCK as u64
        };
        if used != expected
            || used == 0
            || used > BLOCK as u64
            || self.plain[USED + used as usize..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(invalid());
        }
        self.cached = Some(index);
        Ok(())
    }
    fn retire(&mut self) {
        self.poisoned = true;
        self.cached = None;
        self.plain.as_mut_slice().zeroize();
    }
}
impl Read for SpoolReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Err(error) = self.validate_size() {
            self.retire();
            return Err(error);
        }
        if output.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let index = self.position / (BLOCK as u64);
        if let Err(error) = self.load(index) {
            self.retire();
            return Err(error);
        }
        let within = (self.position % (BLOCK as u64)) as usize;
        let count = output
            .len()
            .min(BLOCK - within)
            .min((self.length - self.position).min(BLOCK as u64) as usize);
        output[..count].copy_from_slice(&self.plain[USED + within..USED + within + count]);
        self.position = self
            .position
            .checked_add(count as u64)
            .ok_or_else(exhausted)?;
        Ok(count)
    }
}
impl Seek for SpoolReader {
    fn stream_position(&mut self) -> io::Result<u64> {
        if let Err(error) = self.validate_size() {
            self.retire();
            return Err(error);
        }
        Ok(self.position)
    }
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if let Err(error) = self.validate_size() {
            self.retire();
            return Err(error);
        }
        let position = match from {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        let position = u64::try_from(position).map_err(|_| exhausted())?;
        self.plain.as_mut_slice().zeroize();
        self.cached = None;
        self.position = position;
        Ok(position)
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    pub(super) fn create() -> io::Result<File> {
        let directory = std::env::temp_dir().canonicalize()?;
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory)?;
        let metadata = parent.metadata()?;
        if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
            return Err(failed());
        }
        for _ in 0..16 {
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(|_| failed())?;
            let name =
                std::ffi::CString::new(format!("busbar-source-spool-{}", hex::encode(random)))
                    .map_err(|_| failed())?;
            // SAFETY: retained directory descriptor, terminated random basename,
            // and flags stay live for this exclusive, non-inheritable creation.
            let descriptor = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600 as libc::c_uint,
                )
            };
            if descriptor < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error);
            }
            // SAFETY: successful openat returned this fresh, uniquely owned descriptor.
            let file = unsafe { File::from_raw_fd(descriptor) };
            loop {
                // SAFETY: this name was exclusively created relative to the retained
                // directory descriptor; the file is still empty and owned here.
                if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            let metadata = file.metadata()?;
            if metadata.nlink() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(failed());
            }
            return Ok(file);
        }
        Err(failed())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use windows_sys::Win32::{
        Foundation::{LocalFree, INVALID_HANDLE_VALUE},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, CREATE_NEW, DELETE, FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        },
    };
    pub(super) fn create() -> io::Result<File> {
        let directory = std::env::temp_dir().canonicalize()?;
        let descriptor: Vec<u16> = "D:P(A;;FA;;;OW)".encode_utf16().chain([0]).collect();
        let mut security = std::ptr::null_mut();
        // SAFETY: static-format SDDL is terminated and the output pointer is live.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                descriptor.as_ptr(),
                SDDL_REVISION_1,
                &mut security,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let answer = (|| {
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: security,
                bInheritHandle: 0,
            };
            for _ in 0..16 {
                let mut random = [0; 16];
                getrandom::fill(&mut random).map_err(|_| failed())?;
                let path = directory.join(format!("busbar-source-spool-{}", hex::encode(random)));
                let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
                if path[..path.len() - 1].contains(&0) {
                    return Err(failed());
                }
                // SAFETY: pointers remain live during creation. CREATE_NEW never
                // replaces a file; no handle inheritance or sharing is enabled.
                let handle = unsafe {
                    CreateFileW(
                        path.as_ptr(),
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                        0,
                        &attributes,
                        CREATE_NEW,
                        FILE_ATTRIBUTE_TEMPORARY
                            | FILE_FLAG_DELETE_ON_CLOSE
                            | FILE_FLAG_OPEN_REPARSE_POINT,
                        std::ptr::null_mut(),
                    )
                };
                if handle == INVALID_HANDLE_VALUE {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        continue;
                    }
                    return Err(error);
                }
                // SAFETY: this newly created native handle has exactly one owner.
                return Ok(unsafe { File::from_raw_handle(handle) });
            }
            Err(failed())
        })();
        // SAFETY: successful SDDL conversion allocated this native descriptor.
        unsafe {
            LocalFree(security);
        }
        answer
    }
}
#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    pub(super) fn create() -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "encrypted source spool unavailable on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(file: &mut File) -> Vec<u8> {
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }
    fn source() -> Vec<u8> {
        (0..BLOCK * 2 + 37)
            .map(|index| (index.wrapping_mul(71) % 251) as u8)
            .collect()
    }
    fn reader(bytes: &[u8]) -> SpoolReader {
        let mut writer = SpoolWriter::new().unwrap();
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn bounded_roundtrip_and_checked_logical_seeking() {
        fn send<T: Send>() {}
        send::<SpoolWriter>();
        send::<SpoolReader>();
        for length in [0, 1, BLOCK - 1, BLOCK, BLOCK + 1, BLOCK * 2 + 37] {
            let data = source();
            let data = &data[..length];
            let mut spool = reader(data);
            assert_eq!(spool.plain.len(), PLAIN);
            assert_eq!(spool.encoded.len(), FRAME);
            let mut result = Vec::new();
            spool.read_to_end(&mut result).unwrap();
            assert_eq!(result, data);
            assert_eq!(spool.seek(SeekFrom::End(0)).unwrap(), length as u64);
            if length > 0 {
                spool.seek(SeekFrom::End(-1)).unwrap();
                let mut tail = [0];
                spool.read_exact(&mut tail).unwrap();
                assert_eq!(tail[0], data[length - 1]);
            }
            spool.rewind().unwrap();
            assert!(spool.seek(SeekFrom::Current(-1)).is_err());
            assert_eq!(spool.stream_position().unwrap(), 0);
            spool.seek(SeekFrom::Start(u64::MAX)).unwrap();
            assert!(spool.seek(SeekFrom::Current(1)).is_err());
            assert_eq!(spool.stream_position().unwrap(), u64::MAX);
            assert_eq!(spool.read(&mut [0; 1]).unwrap(), 0);
            if length > BLOCK {
                spool.seek(SeekFrom::Start((BLOCK - 1) as u64)).unwrap();
                let mut crossing = [0; 2];
                spool.read_exact(&mut crossing).unwrap();
                assert_eq!(crossing, data[BLOCK - 1..BLOCK + 1]);
            }
        }
    }

    #[test]
    fn flush_rewrites_only_partial_frame_with_a_fresh_nonce() {
        let mut writer = SpoolWriter::new().unwrap();
        let mut raw = writer.file.try_clone().unwrap();
        writer.write_all(b"spool-plaintext-marker-42").unwrap();
        writer.flush().unwrap();
        let old = image(&mut raw);
        assert_eq!(old.len(), FRAME);
        assert!(!old
            .windows(b"spool-plaintext-marker-42".len())
            .any(|bytes| bytes == b"spool-plaintext-marker-42"));
        writer.flush().unwrap();
        assert_eq!(image(&mut raw), old);
        writer.write_all(b"-second").unwrap();
        writer.flush().unwrap();
        let next = image(&mut raw);
        assert_ne!(&old[..GCM_NONCE_LEN], &next[..GCM_NONCE_LEN]);
        let mut spool = writer.finish().unwrap();
        let mut observed = String::new();
        spool.read_to_string(&mut observed).unwrap();
        assert_eq!(observed, "spool-plaintext-marker-42-second");
        // An authentic earlier flush cannot substitute for the sealed longer
        // final block, even though its tag and block index are otherwise valid.
        raw.rewind().unwrap();
        raw.write_all(&old).unwrap();
        spool.rewind().unwrap();
        let mut output = [0xa5; 12];
        assert_eq!(
            spool.read(&mut output).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(output, [0xa5; 12]);
        assert!(spool.plain.iter().all(|byte| *byte == 0));

        let mut writer = SpoolWriter::new().unwrap();
        let mut raw = writer.file.try_clone().unwrap();
        writer.write_all(&source()[..BLOCK + 7]).unwrap();
        writer.flush().unwrap();
        let before = image(&mut raw);
        writer.write_all(b"append").unwrap();
        writer.flush().unwrap();
        let after = image(&mut raw);
        assert_eq!(
            &before[..FRAME],
            &after[..FRAME],
            "a prior full block is immutable"
        );
        assert_ne!(
            &before[FRAME..FRAME + GCM_NONCE_LEN],
            &after[FRAME..FRAME + GCM_NONCE_LEN]
        );
        let spool = writer.finish().unwrap();
        assert_eq!(spool.length, (BLOCK + 13) as u64);
    }

    #[test]
    fn corruption_truncation_reordering_and_foreign_spools_are_refused() {
        for case in 0..7 {
            let data = source();
            let mut spool = reader(&data);
            let mut raw = spool.file.try_clone().unwrap();
            let mut bytes = image(&mut raw);
            match case {
                0 => bytes[0] ^= 1,
                1 => bytes[GCM_NONCE_LEN + USED] ^= 1,
                2 => bytes[FRAME - 1] ^= 1,
                3 => {
                    let first = bytes[..FRAME].to_vec();
                    let second = bytes[FRAME..FRAME * 2].to_vec();
                    bytes[..FRAME].copy_from_slice(&second);
                    bytes[FRAME..FRAME * 2].copy_from_slice(&first);
                }
                4 => {
                    bytes.pop();
                }
                5 => bytes.push(0),
                6 => {
                    let other = reader(&data);
                    let mut other_file = other.file.try_clone().unwrap();
                    bytes[..FRAME].copy_from_slice(&image(&mut other_file)[..FRAME]);
                }
                _ => unreachable!(),
            }
            raw.set_len(bytes.len() as u64).unwrap();
            raw.rewind().unwrap();
            raw.write_all(&bytes).unwrap();
            let mut output = [0xa5; 32];
            assert_eq!(
                spool.read(&mut output).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "case {case}"
            );
            assert_eq!(output, [0xa5; 32]);
            assert!(spool.plain.iter().all(|byte| *byte == 0));
            assert!(spool.read(&mut output).is_err());
        }
    }

    #[test]
    fn counter_exhaustion_retires_writer_and_wipes_plaintext() {
        let mut writer = SpoolWriter::new().unwrap();
        writer.write_all(b"protected source fixture").unwrap();
        writer.next_nonce = u64::MAX;
        assert!(writer.flush().is_err());
        assert!(writer.plain.iter().all(|byte| *byte == 0));
        assert_eq!(writer.file.metadata().unwrap().len(), 0);
        assert!(writer.write(b"retry").is_err());
        assert!(writer.finish().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn backing_file_is_private_and_already_unlinked_before_any_write() {
        use std::os::unix::fs::MetadataExt;
        let mut writer = SpoolWriter::new().unwrap();
        let metadata = writer.file.metadata().unwrap();
        assert_eq!(metadata.nlink(), 0);
        assert_eq!(metadata.mode() & 0o077, 0);
        writer.write_all(b"not on a filesystem path").unwrap();
        let spool = writer.finish().unwrap();
        assert_eq!(spool.file.metadata().unwrap().nlink(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn backing_file_denies_other_opens_and_is_removed_on_close() {
        use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
        let writer = SpoolWriter::new().unwrap();
        let mut name = vec![0u16; 32768];
        // SAFETY: live retained file handle and initialized bounded output buffer.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                writer.file.as_raw_handle(),
                name.as_mut_ptr(),
                name.len() as u32,
                0,
            )
        } as usize;
        assert!(length > 0 && length < name.len());
        let path = std::path::PathBuf::from(std::ffi::OsString::from_wide(&name[..length]));
        assert!(File::open(&path).is_err());
        drop(writer);
        assert!(!path.exists());
    }
}
