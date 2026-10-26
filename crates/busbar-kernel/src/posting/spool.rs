// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SPOOL ON DISK (MONEY-DESIGN §3c, "The spool", "Segments and the manifest", "A failed
//! `fsync`"). A set of segment files listed in a small `MANIFEST`:
//!
//! - every record is framed ([`super::frame`]) and a round is ONE write and ONE `fsync`;
//! - a generation is switched by writing the manifest to a temporary file, `fsync`ing it, renaming
//!   it over `MANIFEST` and `fsync`ing the directory, so a crash leaves the old or the new
//!   generation, never both;
//! - a failed `fsync` is never appended after: the segment is SEALED at its last synced offset in
//!   the manifest (boot reads it only up to there) and the round is rewritten into a NEW segment;
//! - compaction writes the live records into a new segment, `fsync`s it, then switches the
//!   manifest the same way.
//!
//! The spool takes no lock of its own: one writer task owns it.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::frame;
use super::record::{self, Rec};

/// The manifest's file name.
pub const MANIFEST: &str = "MANIFEST";

/// How a segment is made durable: `sync_data` in production; a test double fails it on demand.
pub trait Syncer: Send + Sync {
    /// Make `file`'s written bytes durable.
    ///
    /// # Errors
    ///
    /// The medium did not confirm the bytes.
    fn sync(&self, file: &File) -> io::Result<()>;
}

/// The production syncer: `File::sync_data`.
pub struct DataSync;

impl Syncer for DataSync {
    fn sync(&self, file: &File) -> io::Result<()> {
        file.sync_data()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SegMeta {
    id: u64,
    /// Sealed at this readable length after a failed `fsync`; `None` while appendable or whole.
    #[serde(default)]
    sealed: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Manifest {
    generation: u64,
    segments: Vec<SegMeta>,
}

/// The spool's directory and its active segment.
pub struct Spool {
    dir: PathBuf,
    manifest: Manifest,
    active: File,
    active_len: u64,
    syncer: Arc<dyn Syncer>,
    fsyncs: Arc<AtomicU64>,
}

impl std::fmt::Debug for Spool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spool")
            .field("dir", &self.dir)
            .field("segments", &self.manifest.segments.len())
            .finish_non_exhaustive()
    }
}

fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("seg-{id:016x}.log"))
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

impl Spool {
    /// Open the spool in `dir` (created if absent) and read back every record it holds, in order.
    /// A torn tail of the active segment is truncated; a sealed segment is read only up to its
    /// seal.
    ///
    /// # Errors
    ///
    /// The directory or a segment could not be read or written.
    pub fn open(dir: &Path, syncer: Arc<dyn Syncer>) -> io::Result<(Spool, Vec<Rec>)> {
        std::fs::create_dir_all(dir)?;
        let fsyncs = Arc::new(AtomicU64::new(0));
        let manifest = match std::fs::read(dir.join(MANIFEST)) {
            Ok(bytes) => {
                let (bodies, _) = frame::read_all(&bytes);
                bodies
                    .first()
                    .and_then(|b| serde_json::from_slice::<Manifest>(b).ok())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "the spool MANIFEST is damaged")
                    })?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Manifest::default(),
            Err(e) => return Err(e),
        };
        let mut records = Vec::new();
        let mut manifest = manifest;
        let last = manifest.segments.last().map(|s| s.id);
        for seg in &manifest.segments {
            let path = seg_path(dir, seg.id);
            let mut bytes = Vec::new();
            match File::open(&path) {
                Ok(mut f) => {
                    f.read_to_end(&mut bytes)?;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            if let Some(limit) = seg.sealed {
                bytes.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
            }
            let (bodies, end) = frame::read_all(&bytes);
            records.extend(bodies.into_iter().filter_map(record::decode));
            if Some(seg.id) == last && seg.sealed.is_none() && end < bytes.len() {
                // A torn tail: no END was released for it. Cut it so the next round appends after
                // the last whole record.
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len(end as u64)?;
                syncer.sync(&f)?;
            }
        }
        // The active segment: the last one unless it is sealed, else a fresh one.
        let reopen = manifest
            .segments
            .last()
            .filter(|s| s.sealed.is_none())
            .map(|s| s.id);
        let (active, active_len) = match reopen {
            Some(id) => {
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .open(seg_path(dir, id))?;
                let len = f.metadata()?.len();
                (f, len)
            }
            None => {
                let id = manifest.segments.last().map_or(1, |s| s.id + 1);
                manifest.segments.push(SegMeta { id, sealed: None });
                manifest.generation += 1;
                let f = Self::create_segment(dir, id, syncer.as_ref())?;
                Self::write_manifest(dir, &manifest, syncer.as_ref())?;
                (f, 0)
            }
        };
        let spool = Spool {
            dir: dir.to_path_buf(),
            manifest,
            active,
            active_len,
            syncer,
            fsyncs,
        };
        Ok((spool, records))
    }

    fn create_segment(dir: &Path, id: u64, syncer: &dyn Syncer) -> io::Result<File> {
        drop(
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(seg_path(dir, id))?,
        );
        let f = OpenOptions::new()
            .append(true)
            .read(true)
            .open(seg_path(dir, id))?;
        syncer.sync(&f)?;
        sync_dir(dir)?;
        Ok(f)
    }

    fn write_manifest(dir: &Path, manifest: &Manifest, syncer: &dyn Syncer) -> io::Result<()> {
        let mut bytes = Vec::new();
        frame::put(
            &mut bytes,
            &serde_json::to_vec(manifest).unwrap_or_default(),
        );
        let tmp = dir.join(format!("{MANIFEST}.tmp"));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            syncer.sync(&f)?;
        }
        std::fs::rename(&tmp, dir.join(MANIFEST))?;
        sync_dir(dir)
    }

    /// How many `fsync`s of a round this spool has made (the rounds' cost, for the T4 witness).
    #[must_use]
    pub fn fsyncs(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.fsyncs)
    }

    /// The bytes the live segments hold.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.manifest
            .segments
            .iter()
            .map(|s| {
                std::fs::metadata(seg_path(&self.dir, s.id))
                    .map(|m| s.sealed.unwrap_or(m.len()).min(m.len()))
                    .unwrap_or(0)
            })
            .sum()
    }

    /// ONE ROUND: `recs` framed into one write, then one `fsync`. A write or `fsync` that fails is
    /// never appended after: the round is re-appended to a NEW segment and synced there FIRST, and
    /// only then is the failed segment sealed at its last synced offset (in a new manifest
    /// generation). `Err` only when that fails too: the spool is then failed, and the caller keeps
    /// the round in RAM.
    ///
    /// # Errors
    ///
    /// Neither the active segment nor a fresh one would take the round durably.
    pub fn append(&mut self, recs: &[Rec]) -> io::Result<()> {
        if recs.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        for r in recs {
            frame::put(&mut buf, &record::encode(r));
        }
        let synced = self.active_len;
        let first = (|| {
            self.active.write_all(&buf)?;
            self.fsyncs.fetch_add(1, Ordering::Relaxed);
            self.syncer.sync(&self.active)
        })();
        match first {
            Ok(()) => {
                self.active_len = synced + buf.len() as u64;
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = %e, dir = %self.dir.display(),
                    "money spool: a round failed to sync; re-appending it to a new segment, then sealing the failed one");
                // In memory the failed segment is sealed at once: nothing is appended after it.
                if let Some(seg) = self.manifest.segments.last_mut() {
                    seg.sealed = Some(synced);
                }
                self.move_to_new_segment(&buf)
            }
        }
    }

    /// The round `buf` into a NEW segment, synced, and only then the manifest generation that
    /// seals the old segment and lists the new one.
    fn move_to_new_segment(&mut self, buf: &[u8]) -> io::Result<()> {
        let next = self.manifest.segments.last().map_or(1, |s| s.id + 1);
        let mut f = Self::create_segment(&self.dir, next, self.syncer.as_ref())?;
        f.write_all(buf)?;
        self.fsyncs.fetch_add(1, Ordering::Relaxed);
        self.syncer.sync(&f)?;
        let mut manifest = self.manifest.clone();
        manifest.segments.push(SegMeta {
            id: next,
            sealed: None,
        });
        manifest.generation += 1;
        Self::write_manifest(&self.dir, &manifest, self.syncer.as_ref())?;
        self.manifest = manifest;
        self.active = f;
        self.active_len = buf.len() as u64;
        Ok(())
    }

    /// Whether the active segment was sealed by a failed round and no new segment has taken over.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.manifest
            .segments
            .last()
            .is_none_or(|s| s.sealed.is_some())
    }

    /// Reopen after a failed round: a fresh segment in a new generation.
    ///
    /// # Errors
    ///
    /// The fresh segment or the manifest could not be written durably.
    pub fn reopen(&mut self) -> io::Result<()> {
        self.move_to_new_segment(&[])
    }

    /// COMPACTION: `live` written into a new segment and synced, then the manifest switched to it
    /// alone, then the old segments removed. A crash leaves either generation, never both.
    ///
    /// # Errors
    ///
    /// The new segment or the manifest could not be written durably; the old generation stands.
    pub fn compact(&mut self, live: &[Rec]) -> io::Result<()> {
        let next = self.manifest.segments.last().map_or(1, |s| s.id + 1);
        let mut f = Self::create_segment(&self.dir, next, self.syncer.as_ref())?;
        let mut buf = Vec::new();
        for r in live {
            frame::put(&mut buf, &record::encode(r));
        }
        f.write_all(&buf)?;
        self.fsyncs.fetch_add(1, Ordering::Relaxed);
        self.syncer.sync(&f)?;
        let old: Vec<u64> = self.manifest.segments.iter().map(|s| s.id).collect();
        let manifest = Manifest {
            generation: self.manifest.generation + 1,
            segments: vec![SegMeta {
                id: next,
                sealed: None,
            }],
        };
        Self::write_manifest(&self.dir, &manifest, self.syncer.as_ref())?;
        self.manifest = manifest;
        self.active = f;
        self.active_len = buf.len() as u64;
        for id in old {
            let _ = std::fs::remove_file(seg_path(&self.dir, id));
        }
        Ok(())
    }

    /// Discard every segment and the manifest (an ephemeral store restarts at zero).
    ///
    /// # Errors
    ///
    /// The directory could not be cleared.
    pub fn discard(dir: &Path) -> io::Result<()> {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for e in entries.flatten() {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with("seg-") || name.starts_with(MANIFEST) {
                        std::fs::remove_file(e.path())?;
                    }
                }
                sync_dir(dir)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// A small framed, append-only, synced file: the DEAD-LETTER file beside the spool.
#[derive(Debug)]
pub struct Ledgerette {
    path: PathBuf,
}

impl Ledgerette {
    /// The file at `path`.
    #[must_use]
    pub fn at(path: PathBuf) -> Self {
        Ledgerette { path }
    }

    /// Every whole record body in the file.
    ///
    /// # Errors
    ///
    /// The file exists and could not be read.
    pub fn read(&self) -> io::Result<Vec<Vec<u8>>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(frame::read_all(&bytes)
                .0
                .into_iter()
                .map(<[u8]>::to_vec)
                .collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// Append `bodies` in one write and one `fsync`.
    ///
    /// # Errors
    ///
    /// The bytes could not be made durable.
    pub fn append(&self, bodies: &[Vec<u8>]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let existed = self.path.exists();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut buf = Vec::new();
        for b in bodies {
            frame::put(&mut buf, b);
        }
        f.write_all(&buf)?;
        f.sync_data()?;
        if !existed {
            if let Some(parent) = self.path.parent() {
                sync_dir(parent)?;
            }
        }
        Ok(())
    }

    /// REWRITE the file as `bodies` (compaction): a temporary file, synced, renamed over it, the
    /// directory synced.
    ///
    /// # Errors
    ///
    /// The new file could not be made durable; the old one stands.
    pub fn rewrite(&self, bodies: &[Vec<u8>]) -> io::Result<()> {
        let Some(parent) = self.path.parent() else {
            return Err(io::Error::other("the dead-letter file has no directory"));
        };
        let tmp = self.path.with_extension("tmp");
        let mut buf = Vec::new();
        for b in bodies {
            frame::put(&mut buf, b);
        }
        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)?;
            f.write_all(&buf)?;
            f.sync_data()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        sync_dir(parent)
    }

    /// Remove the file (an ephemeral store keeps no dead letters across a restart).
    ///
    /// # Errors
    ///
    /// The file exists and could not be removed.
    pub fn discard(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "tests/spool_tests.rs"]
mod tests;
