// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Where a segment's bytes actually live, behind a seam narrow enough to lie about.
//!
//! There are two production backings and one test backing, and they are the same three lines of
//! interface: write at an offset, make the write durable, read back, say how long you are, and
//! shorten yourself. A file backing does that with positional writes and a data sync. A memory
//! backing does it with a `Vec`, and its sync is a no-op because there is nothing under it to
//! survive a crash — which is precisely the honest statement of what a deployment with no data
//! directory has.
//!
//! The seam exists for one reason beyond tidiness: a disk that returns a write error at a sync
//! point is the single most important thing this crate has to get right, and there is no way to
//! make a real disk do that on demand inside a test. A backing that can be told to fail is how the
//! poison rule becomes a checked property rather than a claim.

use std::io;
use std::path::{Path, PathBuf};

/// One segment's storage.
///
/// Implementations are not required to be crash-safe by themselves; they are required to report a
/// failure at [`SegmentBackend::sync`] honestly, because the caller turns that report into a
/// poisoned segment and a durability loss.
pub trait SegmentBackend: Send {
    /// Write `bytes` starting at `offset`, in full. A short write is an error, not a partial
    /// success — the caller has no way to make a partial group commit mean anything.
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()>;

    /// Make everything written so far durable. This is the point the poison rule hangs on.
    fn sync(&mut self) -> io::Result<()>;

    /// Read into `buf` starting at `offset`, returning how many bytes were available. Short reads
    /// at the end of the backing are ordinary.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// How long the backing currently is.
    fn len(&self) -> io::Result<u64>;

    /// Whether the backing holds nothing at all.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Grow or shrink the backing to exactly `len`. Growing is how space is preallocated; the new
    /// space reads as zeros, which is exactly what a frame scan treats as the end of the writes.
    fn set_len(&mut self, len: u64) -> io::Result<()>;
}

/// How a segment comes into being. The log asks for segment `index` and is handed a backing.
///
/// This is also where "no data directory means no file anywhere" is enforced by construction
/// rather than by a check: the memory factory has no path to write to, so there is no code path
/// from a memory-backed log to a file system at all.
pub trait SegmentFactory: Send {
    /// Open, or create, the backing for segment `index`.
    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>>;

    /// Whether this factory can put anything on a disk. A memory factory says no, and the log
    /// reports it so an operator can see which mode a node is in without inspecting a directory.
    fn is_durable(&self) -> bool;
}

/// The bytes of one memory segment, shared so that closing and reopening a segment — which is what
/// a restart looks like from inside a test — finds what was written to it before.
pub type SharedBytes = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

/// A segment kept in memory. The backing for a deployment with no data directory, and the base a
/// test backing wraps to inject failures.
#[derive(Debug, Default, Clone)]
pub struct MemorySegment {
    bytes: SharedBytes,
}

impl MemorySegment {
    /// An empty segment.
    pub fn new() -> Self {
        MemorySegment::default()
    }

    /// A segment over bytes that already exist — the way a test poses a torn tail.
    pub fn over(bytes: SharedBytes) -> Self {
        MemorySegment { bytes }
    }

    /// A snapshot of the bytes as they stand, so a test can truncate them and hand them back.
    pub fn snapshot(&self) -> Vec<u8> {
        self.bytes.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The shared bytes themselves, so a caller can reopen the same segment later.
    pub fn shared(&self) -> SharedBytes {
        std::sync::Arc::clone(&self.bytes)
    }
}

impl SegmentBackend for MemorySegment {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset beyond memory"))?;
        let end = start + bytes.len();
        let mut held = self.bytes.lock().unwrap_or_else(|e| e.into_inner());
        if held.len() < end {
            held.resize(end, 0);
        }
        held[start..end].copy_from_slice(bytes);
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        // Nothing underneath to flush to. Saying so plainly is better than pretending: a
        // memory-buffered log's durability is whatever the store it ships to provides.
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        let held = self.bytes.lock().unwrap_or_else(|e| e.into_inner());
        if start >= held.len() {
            return Ok(0);
        }
        let n = usize::min(buf.len(), held.len() - start);
        buf[..n].copy_from_slice(&held[start..start + n]);
        Ok(n)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.bytes.lock().unwrap_or_else(|e| e.into_inner()).len() as u64)
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        let len = usize::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "length beyond memory"))?;
        self.bytes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .resize(len, 0);
        Ok(())
    }
}

/// Hands out memory segments. The default, and the only backing a node without a data directory
/// ever sees.
#[derive(Debug, Default, Clone)]
pub struct MemoryFactory {
    segments: std::sync::Arc<std::sync::Mutex<Vec<SharedBytes>>>,
}

impl MemoryFactory {
    /// A factory with no segments yet.
    pub fn new() -> Self {
        MemoryFactory::default()
    }

    /// The shared bytes of segment `index`, creating the slot if it does not exist yet. A test uses
    /// this to reach in and damage a tail.
    pub fn segment_bytes(&self, index: u64) -> SharedBytes {
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        let mut held = self.segments.lock().unwrap_or_else(|e| e.into_inner());
        while held.len() <= index {
            held.push(SharedBytes::default());
        }
        std::sync::Arc::clone(&held[index])
    }

    /// How many segments have been opened.
    pub fn segment_count(&self) -> usize {
        self.segments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

impl SegmentFactory for MemoryFactory {
    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>> {
        Ok(Box::new(MemorySegment::over(self.segment_bytes(index))))
    }

    fn is_durable(&self) -> bool {
        false
    }
}

/// A segment that is a file under the data directory.
#[derive(Debug)]
pub struct FileSegment {
    file: std::fs::File,
}

impl FileSegment {
    /// Open, creating if absent, the file at `path`.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        Ok(FileSegment { file })
    }
}

impl SegmentBackend for FileSegment {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            self.file.write_all_at(bytes, offset)
        }
        #[cfg(not(unix))]
        {
            use std::io::{Seek as _, SeekFrom, Write as _};
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(bytes)
        }
    }

    fn sync(&mut self) -> io::Result<()> {
        // The data sync, not the full sync: the record bytes have to be on the medium, and the
        // file's own metadata timestamps do not have to be, so the extra round trip buys nothing.
        self.file.sync_data()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            self.file.read_at(buf, offset)
        }
        #[cfg(not(unix))]
        {
            use std::io::{Read as _, Seek as _, SeekFrom};
            let mut file = &self.file;
            file.seek(SeekFrom::Start(offset))?;
            file.read(buf)
        }
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
}

/// Hands out file segments named `<index>.wal` inside one directory.
#[derive(Debug)]
pub struct DirectoryFactory {
    dir: PathBuf,
}

impl DirectoryFactory {
    /// A factory over `dir`. The directory is created if it is absent — but note that CONSTRUCTING
    /// this type is already the decision to write to a disk. A node with no data directory never
    /// builds one, which is why it leaves no files behind.
    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(DirectoryFactory { dir })
    }

    /// The path segment `index` lives at.
    pub fn segment_path(&self, index: u64) -> PathBuf {
        self.dir.join(format!("{index:016}.wal"))
    }
}

impl SegmentFactory for DirectoryFactory {
    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>> {
        Ok(Box::new(FileSegment::open(&self.segment_path(index))?))
    }

    fn is_durable(&self) -> bool {
        true
    }
}
