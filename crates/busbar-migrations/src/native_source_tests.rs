use super::*;
use crate::Error;
use crate::{archive_source::Grouping, legacy::group::LogicalGroup};
use busbar_contract::persistence::{
    axis::OpenedBackend, lifecycle::*, BackendInfo, DatasetId, Durability,
};
use std::{
    io::{ErrorKind, SeekFrom},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
use zeroize::Zeroizing;

struct MemoryWriter(Zeroizing<Vec<u8>>);
struct MemoryReader {
    bytes: Zeroizing<Vec<u8>>,
    position: u64,
}
impl Write for MemoryWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl SourceSpool for MemoryWriter {
    fn finish(self: Box<Self>) -> io::Result<Box<dyn ReadSeek + Send>> {
        Ok(Box::new(MemoryReader {
            bytes: self.0,
            position: 0,
        }))
    }
}
impl Read for MemoryReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let start =
            usize::try_from(self.position).map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let n = out.len().min(self.bytes.len() - start);
        out[..n].copy_from_slice(&self.bytes[start..start + n]);
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for MemoryReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let value = match to {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(n) => self.bytes.len() as i128 + i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
        };
        self.position =
            u64::try_from(value).map_err(|_| io::Error::from(ErrorKind::InvalidInput))?;
        Ok(self.position)
    }
}
struct Factory;
impl SpoolFactory for Factory {
    fn create(&self) -> io::Result<Box<dyn SourceSpool>> {
        Ok(Box::new(MemoryWriter(Zeroizing::new(Vec::new()))))
    }
}
fn source() -> SourceIdentity {
    SourceIdentity {
        native_anchor: [1; 32],
        dataset: DatasetId([2; 16]),
        format: Some(native::Format {
            owner: SQLITE_SOURCE_OWNER,
            physical: 6,
            logical: 0,
            codec: 1,
        }),
        catalogue_digest: [3; 32],
        layout_digest: [4; 32],
    }
}
fn info() -> BackendInfo {
    BackendInfo {
        dataset: DatasetId([6; 16]),
        atomic_domain: [7; 16],
        clock_authority: [8; 16],
        physical_version: 1,
        durability: Durability::Local,
    }
}
fn upgrade() -> Upgrade {
    Upgrade {
        reference: UpgradeRef {
            id: [9; 16],
            authority: Secret::new(b"owned-authority".to_vec()),
        },
        source: source(),
        snapshot: [5; 16],
        target: info(),
        native_step: 1,
        catalogue: vec![Table {
            name: "extra".into(),
            columns: vec!["number".into()],
            native_layout: b"native integer".to_vec(),
        }],
    }
}
fn row() -> Secret<Vec<u8>> {
    let mut bytes = b"BBLROW01".to_vec();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&9i64.to_le_bytes());
    Secret::new(bytes)
}
#[derive(Default)]
struct Prepared {
    pages: AtomicUsize,
    fences: AtomicUsize,
    request: Mutex<Option<usize>>,
    wrong_snapshot: bool,
}
impl PreparedStore for Prepared {
    fn phase(&self) -> Phase {
        Phase::Upgrading
    }
    fn bootstrap(&self, request: Arc<Request>) -> BootstrapCall<'_> {
        Box::pin(async move {
            match request.as_ref() {
                Request::CheckFence { .. } => {
                    let n = self.fences.fetch_add(1, Ordering::SeqCst) + 1;
                    Ok(Arc::new(Response::Fence(Fence {
                        upgrade: [9; 16],
                        source: source(),
                        enforcement_digest: [10; 32],
                        observation_digest: [n as u8; 32],
                        snapshot: [5; 16],
                    })))
                }
                Request::SourcePage {
                    snapshot,
                    family,
                    selector,
                    cursor,
                    ..
                } => {
                    assert_eq!(*snapshot, [5; 16]);
                    assert_eq!(*family, source().format.unwrap().owner);
                    assert!(cursor.is_none());
                    assert!(matches!(selector, SourceSelector::Scan { table: 0 }));
                    let pointer = Arc::as_ptr(&request) as usize;
                    if self.pages.fetch_add(1, Ordering::SeqCst) == 0 {
                        *self.request.lock().unwrap() = Some(pointer);
                        return Err(native::Error::Unknown);
                    }
                    assert_eq!(
                        *self.request.lock().unwrap(),
                        Some(pointer),
                        "read-only unknown retries the exact Arc/cursor"
                    );
                    Ok(Arc::new(Response::SourcePage(native::SourcePage {
                        snapshot: if self.wrong_snapshot {
                            [11; 16]
                        } else {
                            *snapshot
                        },
                        family: *family,
                        rows: vec![SourceRow {
                            table: 0,
                            native_key: Secret::new(b"native-key".to_vec()),
                            value: row(),
                        }],
                        next: None,
                        source_digest: [12; 32],
                        coverage_digest: [13; 32],
                    })))
                }
                _ => Err(native::Error::MissingCapability),
            }
        })
    }
    fn target(&self, _: UpgradeRef) -> TargetCall<'_> {
        Box::pin(async { Err(native::Error::MissingCapability) })
    }
    fn open(&self, _: OpenBinding) -> PreparedOpenCall<'_> {
        Box::pin(async { Err(native::Error::MissingCapability) })
    }
    fn serving(&self) -> Result<OpenedBackend, native::Error> {
        Err(native::Error::MissingCapability)
    }
}
struct Groups;
impl Grouping for Groups {
    fn classify(
        &self,
        _: &Header,
        _: &Table,
        key: &[u8],
        _: busbar_contract::persistence::legacy_row::Row<'_>,
    ) -> Result<LogicalGroup, Error> {
        Ok(LogicalGroup {
            family: crate::legacy::transform::ARCHIVAL,
            key: Secret::new(key.to_vec()),
        })
    }
}
fn limits() -> archive::Limits {
    archive::Limits {
        frame_bytes: 4096,
        total_bytes: 65536,
        rows: 8,
        tables: 2,
        columns: 8,
        index_bytes: 16384,
    }
}
#[tokio::test]
async fn live_capture_keeps_native_lineage_and_session_without_inventing_offline_fence() {
    let prepared = Arc::new(Prepared::default());
    let weak = Arc::downgrade(&prepared);
    let native_upgrade = upgrade();
    let mut frozen = NativeSnapshot::capture(
        prepared.clone(),
        &native_upgrade,
        Bounds {
            items: 8,
            bytes: 4096,
        },
        &Factory,
        limits(),
    )
    .await
    .unwrap();
    assert_eq!(prepared.pages.load(Ordering::SeqCst), 2);
    assert_eq!(prepared.fences.load(Ordering::SeqCst), 2);
    assert_eq!(frozen.identity().dataset, [2; 16]);
    assert_eq!(frozen.identity().product_release, [0, 0, 0]);
    assert_eq!(frozen.snapshot().snapshot, [5; 16]);
    assert_eq!(frozen.header().native_anchor_digest, [1; 32]);
    assert_eq!(
        frozen.archive.header().native_anchor_digest,
        [0; 32],
        "inner artifact claims only immutable bytes"
    );
    assert!(frozen.archive.header().capture.is_none());
    assert_eq!(frozen.rows().row_count(), 1);
    let original = frozen.rows().read_row(0).unwrap();
    let seal = crate::seal::lend();
    assert_eq!(original.value, row());
    assert_eq!(original.native_key.expose(&seal), b"native-key");
    let source = frozen
        .into_source(Arc::new(Groups), 16384, 4096, [0, 0, 0])
        .unwrap();
    assert_eq!(source.identity().dataset, [2; 16]);
    assert_eq!(source.identity().schema_digest, [3; 32]);
    assert_eq!(source.snapshot().snapshot, [5; 16]);
    drop(prepared);
    assert!(
        weak.upgrade().is_some(),
        "native ownership survives source projection"
    );
    drop(source);
    assert!(weak.upgrade().is_none());
}
#[tokio::test]
async fn capture_refuses_native_snapshot_substitution_before_exposing_rows() {
    let prepared = Arc::new(Prepared {
        wrong_snapshot: true,
        ..Prepared::default()
    });
    assert!(matches!(
        NativeSnapshot::capture(
            prepared,
            &upgrade(),
            Bounds {
                items: 8,
                bytes: 4096
            },
            &Factory,
            limits()
        )
        .await,
        Err(Error::Corrupt)
    ));
}

#[tokio::test]
async fn resumed_native_capture_coverage_excludes_fresh_fence_challenges() {
    let mut first = None;
    for offset in [0, 20] {
        let prepared = Arc::new(Prepared {
            fences: AtomicUsize::new(offset),
            ..Prepared::default()
        });
        let captured = NativeSnapshot::capture(
            prepared,
            &upgrade(),
            Bounds {
                items: 8,
                bytes: 4096,
            },
            &Factory,
            limits(),
        )
        .await
        .unwrap();
        if let Some(expected) = &first {
            assert_eq!(&captured.snapshot(), expected);
        } else {
            first = Some(captured.snapshot());
        }
    }
}
