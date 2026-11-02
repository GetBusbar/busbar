// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Where a segment's bytes actually live, behind a seam narrow enough to lie about.

use std::io;
use std::path::{Path, PathBuf};

/// One segment's storage.

pub trait SegmentBackend: Send {
    /// Write `bytes` starting at `offset`, in full. A short write is an error, not a partial

    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()>;

    /// Make everything written so far durable. This is the point the poison rule hangs on.
    fn sync(&mut self) -> io::Result<()>;

    /// Read into `buf` starting at `offset`, returning how many bytes were available. Short reads

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// How long the backing currently is.
    fn len(&self) -> io::Result<u64>;

    /// Whether the backing holds nothing at all.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Grow or shrink the backing to exactly `len`. Growing is how space is preallocated; the new

    fn set_len(&mut self, len: u64) -> io::Result<()>;
}

/// How a segment comes into being. The log asks for segment `index` and is handed a backing.

pub trait SegmentFactory: Send {
    /// Open, or create, the backing for segment `index`.
    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>>;

    /// The highest index this factory already has a backing for, or `None` when it has none.

    fn highest_index(&self) -> io::Result<Option<u64>>;

    /// The backing for segment `index` if this factory already has one, for READING; `None` when

    fn existing(&self, index: u64) -> io::Result<Option<Box<dyn SegmentBackend>>>;

    /// Whether this factory can put anything on a disk. A memory factory says no, and the log

    fn is_durable(&self) -> bool;

    /// The file segment `index` lives in, on a factory that keeps files.
    fn segment_file(&self, index: u64) -> Option<PathBuf>;

    /// Keep `bytes` — the damaged remainder of segment `index`, starting at `offset`, found at

    fn quarantine(
        &mut self,
        index: u64,
        offset: u64,
        unix_ms: u64,
        bytes: &[u8],
    ) -> io::Result<Option<PathBuf>>;
}

/// One remainder a memory factory set aside: which segment, from which byte, and the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedBytes {
    /// Which segment they came out of.
    pub segment: u64,
    /// The byte offset inside it they started at.
    pub offset: u64,
    /// The bytes, exactly as they stood.
    pub bytes: Vec<u8>,
}

/// The bytes of one memory segment, shared so that closing and reopening a segment — which is what

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

/// What a factory remembers about the segments it has handed out.
///
/// The slots are WEAK on purpose. A memory-backed log rolls to a fresh segment when the current one
/// fills or is poisoned, and it drops the one it left behind — so a factory that held a strong
/// reference to every index it had ever opened would be the one thing keeping a rolled-past
/// segment's ceiling alive, forever, on precisely the deployment that has no disk to spill it to.
/// Holding the slots weakly means the factory can still hand the SAME bytes back to a caller that
/// asks for a segment that is still open, and stops being a reason for a closed one to stay resident.
#[derive(Debug, Default)]
struct Segments {
    /// The segments somebody is still holding, by index. Keyed rather than indexed, and swept of
    /// dead entries as it goes, so that the table itself does not become the small version of the
    /// same leak on a node that has rolled through segments for a year.
    slots: std::collections::HashMap<u64, std::sync::Weak<std::sync::Mutex<Vec<u8>>>>,
    /// Strong references, kept only by a retaining factory.
    retained: Vec<SharedBytes>,
    /// Whether this factory keeps every segment alive itself.
    retain: bool,
    /// What recovery set aside from a corrupt segment. Never dropped: nothing is deleted.
    quarantined: Vec<QuarantinedBytes>,
}

/// Hands out memory segments. The default, and the only backing a node without a data directory
/// ever sees.
#[derive(Debug, Default, Clone)]
pub struct MemoryFactory {
    segments: std::sync::Arc<std::sync::Mutex<Segments>>,
}

impl MemoryFactory {
    /// A factory with no segments yet, keeping nothing the log has finished with.
    pub fn new() -> Self {
        MemoryFactory::default()
    }

    /// A factory that keeps every segment's bytes alive for as long as it itself lives.

    pub fn retaining() -> Self {
        let factory = MemoryFactory::default();
        factory
            .segments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain = true;
        factory
    }

    /// The shared bytes of segment `index`, creating the slot if it does not exist yet — or if the

    pub fn segment_bytes(&self, index: u64) -> SharedBytes {
        let mut held = self.segments.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bytes) = held.slots.get(&index).and_then(std::sync::Weak::upgrade) {
            return bytes;
        }
        held.slots.retain(|_, slot| slot.strong_count() > 0);
        let bytes = SharedBytes::default();
        held.slots.insert(index, std::sync::Arc::downgrade(&bytes));
        if held.retain {
            held.retained.push(std::sync::Arc::clone(&bytes));
        }
        bytes
    }

    /// How many segments' bytes are still resident. On a log that is writing, that is the segment it

    pub fn segment_count(&self) -> usize {
        self.segments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .slots
            .values()
            .filter(|slot| slot.strong_count() > 0)
            .count()
    }
}

impl MemoryFactory {
    /// Every remainder recovery has set aside on this factory, oldest first.
    pub fn quarantined(&self) -> Vec<QuarantinedBytes> {
        self.segments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .quarantined
            .clone()
    }
}

impl SegmentFactory for MemoryFactory {
    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>> {
        Ok(Box::new(MemorySegment::over(self.segment_bytes(index))))
    }

    /// The highest index whose bytes are still resident. A slot whose only references are gone is

    fn highest_index(&self) -> io::Result<Option<u64>> {
        Ok(self
            .segments
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .slots
            .iter()
            .filter(|(_, slot)| slot.strong_count() > 0)
            .map(|(index, _)| *index)
            .max())
    }

    /// The bytes of segment `index` while somebody still holds them. A segment a non-retaining

    fn existing(&self, index: u64) -> io::Result<Option<Box<dyn SegmentBackend>>> {
        let held = self.segments.lock().unwrap_or_else(|e| e.into_inner());
        Ok(held
            .slots
            .get(&index)
            .and_then(std::sync::Weak::upgrade)
            .map(|bytes| Box::new(MemorySegment::over(bytes)) as Box<dyn SegmentBackend>))
    }

    fn is_durable(&self) -> bool {
        false
    }

    fn segment_file(&self, _index: u64) -> Option<PathBuf> {
        None
    }

    fn quarantine(
        &mut self,
        index: u64,
        offset: u64,
        _unix_ms: u64,
        bytes: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        let kept = QuarantinedBytes {
            segment: index,
            offset,
            bytes: bytes.to_vec(),
        };
        let mut held = self.segments.lock().unwrap_or_else(|e| e.into_inner());

        if !held.quarantined.contains(&kept) {
            held.quarantined.push(kept);
        }
        Ok(None)
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

    /// Open the file at `path`, creating it if absent, and say whether it was CREATED.

    fn open_reporting(path: &Path) -> io::Result<(Self, bool)> {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => Ok((FileSegment { file }, true)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Ok((FileSegment::open(path)?, false))
            }
            Err(e) => Err(e),
        }
    }

    /// Open the file at `path` for reading only, or `None` when there is no such file.
    pub fn open_existing(path: &Path) -> io::Result<Option<Self>> {
        match std::fs::File::open(path) {
            Ok(file) => Ok(Some(FileSegment { file })),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
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

    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        create_dir_durably(&dir)?;
        Ok(DirectoryFactory { dir })
    }

    /// The path segment `index` lives at.
    pub fn segment_path(&self, index: u64) -> PathBuf {
        self.dir.join(format!("{index:016}.wal"))
    }

    /// A quarantine copy of `segment_name` already in the directory that holds exactly `bytes`.

    fn identical_copy(&self, segment_name: &str, bytes: &[u8]) -> io::Result<Option<PathBuf>> {
        let prefix = format!("{segment_name}.quarantine-");
        let mut candidates: Vec<PathBuf> = std::fs::read_dir(&self.dir)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix))
            })
            .collect();
        candidates.sort();
        for path in candidates {
            let same_length = std::fs::metadata(&path)
                .map(|m| m.len() == bytes.len() as u64)
                .unwrap_or(false);
            if same_length && std::fs::read(&path).is_ok_and(|held| held == bytes) {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    /// The index a file name in the directory stands for, or `None` if this crate did not name it.

    fn index_of(name: &str) -> Option<u64> {
        let digits = name.strip_suffix(".wal")?;
        if digits.len() != 16 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    }
}

impl SegmentFactory for DirectoryFactory {
    /// A NEW segment's directory entry is made durable before the segment is handed out.

    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>> {
        let path = self.segment_path(index);
        let (segment, created) = FileSegment::open_reporting(&path)?;
        if created {
            if let Err(e) = sync_holding_dir(&path) {
                drop(segment);

                let _removed = std::fs::remove_file(&path);
                return Err(e);
            }
        }
        Ok(Box::new(segment))
    }

    /// The highest-numbered `<index>.wal` in the directory. A listing, not a side file: the

    fn highest_index(&self) -> io::Result<Option<u64>> {
        let mut highest: Option<u64> = None;
        for entry in std::fs::read_dir(&self.dir)? {
            let name = entry?.file_name();
            let Some(index) = name.to_str().and_then(DirectoryFactory::index_of) else {
                continue;
            };
            highest = Some(highest.map_or(index, |h: u64| h.max(index)));
        }
        Ok(highest)
    }

    fn existing(&self, index: u64) -> io::Result<Option<Box<dyn SegmentBackend>>> {
        Ok(FileSegment::open_existing(&self.segment_path(index))?
            .map(|file| Box::new(file) as Box<dyn SegmentBackend>))
    }

    fn is_durable(&self) -> bool {
        true
    }

    fn segment_file(&self, index: u64) -> Option<PathBuf> {
        Some(self.segment_path(index))
    }

    /// `<segment>.quarantine-<unix_ms>` beside the segment, created fresh — never over an existing

    fn quarantine(
        &mut self,
        index: u64,
        _offset: u64,
        unix_ms: u64,
        bytes: &[u8],
    ) -> io::Result<Option<PathBuf>> {
        use std::io::Write as _;
        let segment = self.segment_path(index);
        let segment_name = segment
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(path) = self.identical_copy(&segment_name, bytes)? {
            return Ok(Some(path));
        }
        let stem = format!("{segment_name}.quarantine-{unix_ms}");
        let mut attempt = 0u32;
        let (path, mut file) = loop {
            let name = if attempt == 0 {
                stem.clone()
            } else {
                format!("{stem}-{attempt}")
            };
            let path = self.dir.join(name);
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => break (path, file),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && attempt < 1024 => {
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        };
        file.write_all(bytes)?;

        file.sync_all()?;
        sync_holding_dir(&path)?;
        Ok(Some(path))
    }
}

/// The directory whose ENTRY creating or removing `path` changes. A relative `path` with no parent

fn holding_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// fsync the directory that holds `path`, so creating it is itself durable.

fn sync_holding_dir(path: &Path) -> io::Result<()> {
    match sync_dir(holding_dir(path)) {
        Err(e) if fsync_unsupported(&e) => Ok(()),
        other => other,
    }
}

/// fsync `dir` itself, every failure reported. [`sync_holding_dir`] decides which are the caller's.
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(test)]
    crate::tests::hooks::parent_fsync(dir)?;
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }

    #[cfg(not(unix))]
    {
        let _no_barrier = dir;
        Ok(())
    }
}

/// Whether `e` is a filesystem saying a directory cannot be fsynced at all, as opposed to failing to

fn fsync_unsupported(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
    )
}

/// DURABLY create `path` and any missing ancestors: each directory actually created has its PARENT

fn create_dir_durably(path: &Path) -> io::Result<()> {
    let mut missing: Vec<&Path> = Vec::new();
    let mut cur = Some(path);
    while let Some(p) = cur {
        if p.as_os_str().is_empty() || p.exists() {
            break;
        }
        missing.push(p);
        cur = p.parent();
    }
    for dir in missing.iter().rev() {
        match std::fs::create_dir(dir) {
            Ok(()) => sync_holding_dir(dir)?,

            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
