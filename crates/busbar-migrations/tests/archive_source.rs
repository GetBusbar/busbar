use busbar_contract::{
    persistence::{
        archive::{self, Header, Limits, Table, Writer},
        legacy_row::{self, Cell, Row},
    },
    Secret,
};
use busbar_migrations::{
    archive_source::{ArchiveSource, Grouping},
    legacy::group::LogicalGroup,
    Bounds, Edge, Error, Family, Record, SourceReader, TargetRow, Transform,
};
use std::{
    io::{Cursor, Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
};

busbar_contract::own_seal!(Own);
const FAMILY: [u8; 16] = *b"test.groups.v1\0\0";
struct Groups;
impl Grouping for Groups {
    fn classify(
        &self,
        _: &Header,
        _: &Table,
        _: &[u8],
        row: Row<'_>,
    ) -> Result<LogicalGroup, Error> {
        let Some(Cell::Integer(group)) = row.cells().next() else {
            return Err(Error::Corrupt);
        };
        Ok(LogicalGroup {
            family: FAMILY,
            key: Secret::new(group.to_be_bytes().to_vec()),
        })
    }
}
struct Expands(Edge, bool);
impl Transform for Expands {
    fn edge(&self) -> &Edge {
        &self.0
    }
    fn authorize(&self, family: &Family, address: &busbar_contract::persistence::Address) -> bool {
        address.namespace == family.target_namespace
    }
    fn transform(
        &self,
        family: &Family,
        records: &[Record],
        _: Bounds,
    ) -> Result<Vec<TargetRow>, Error> {
        let mut rows = Vec::new();
        for (index, record) in records.iter().enumerate() {
            for copy in 0..2 {
                let mut key = if self.1 { vec![] } else { record.key.clone() };
                key.push(copy);
                rows.push(TargetRow {
                    address: busbar_contract::persistence::Address {
                        namespace: family.target_namespace,
                        key,
                    },
                    value: record.value.clone(),
                    preserved_source: (copy == 0).then_some(index as u32),
                });
            }
        }
        Ok(rows)
    }
}
fn archive_bytes() -> (Vec<u8>, Limits) {
    let limits = Limits {
        frame_bytes: 4096,
        total_bytes: 65536,
        rows: 16,
        tables: 2,
        columns: 8,
        index_bytes: 8192,
    };
    let header = Header {
        owner: *b"legacy.sqlite.v1",
        physical: 6,
        catalogue_digest: archive::digest(b"catalogue"),
        native_anchor_digest: [0; 32],
        capture: None,
        tables: vec![Table {
            name: "rows".into(),
            columns: vec!["group".into(), "value".into()],
            native_layout: b"native facts".to_vec(),
        }],
    };
    let mut writer = Writer::new(Vec::new(), header, limits).unwrap();
    for (ordinal, group) in [1, 2, 1].into_iter().enumerate() {
        let raw = legacy_row::encode::<Own>(
            &[Cell::Integer(group), Cell::Blob(b"opaque-private-value")],
            4096,
        )
        .unwrap();
        writer
            .write_row(
                0,
                &(ordinal as u64).to_le_bytes(),
                raw.expose_own(&Own::here()),
            )
            .unwrap();
    }
    (writer.finish().unwrap().0, limits)
}
fn archive() -> archive::VerifiedArchive<Cursor<Vec<u8>>> {
    let (bytes, limits) = archive_bytes();
    archive::read(Cursor::new(bytes), limits).unwrap()
}
struct SharedRead(Arc<Mutex<Cursor<Vec<u8>>>>);
impl Read for SharedRead {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().read(bytes)
    }
}
impl Seek for SharedRead {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.0.lock().unwrap().seek(position)
    }
}
fn family() -> Family {
    Family {
        id: FAMILY,
        source_schema: 6,
        target_schema: 1,
        target_namespace: [2; 16],
    }
}
#[tokio::test]
async fn pages_join_nonadjacent_native_rows_and_never_split_a_complete_group() {
    let source = ArchiveSource::open(archive(), Arc::new(Groups), 8192, [1, 5, 5]).unwrap();
    let group_key = Secret::new(1i64.to_be_bytes().to_vec());
    let bounds = Bounds {
        items: 2,
        bytes: 4096,
    };
    assert_eq!(
        source
            .read_group_sync(FAMILY, &group_key, bounds)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        source
            .read_group(FAMILY, &group_key, bounds)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(matches!(
        source.read_group_sync(
            FAMILY,
            &group_key,
            Bounds {
                items: 1,
                bytes: 4096
            }
        ),
        Err(Error::Bounds)
    ));
    assert!(matches!(
        source.read_group_sync(FAMILY, &group_key, Bounds { items: 2, bytes: 1 }),
        Err(Error::Bounds)
    ));
    let mut groups = 0;
    source
        .visit_group_keys(FAMILY, &mut |_| {
            groups += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(groups, 2);
    let snapshot = source.snapshot();
    let one = source
        .page(
            &snapshot,
            &family(),
            0,
            Bounds {
                items: 1,
                bytes: 4096,
            },
        )
        .await
        .unwrap();
    assert_eq!(one.records.len(), 1);
    assert_eq!(
        one.next, 2,
        "one tiny marker covers nonadjacent group members"
    );
    assert!(!one.records[0].preserve_exact);
    assert_eq!(one.records[0].value.expose_own(&Own::here()).len(), 72);
    assert_eq!(
        busbar_migrations::legacy::projection::decode_marker(&one.records[0]).unwrap(),
        busbar_migrations::legacy::projection::ProjectionSource::inventory_digest(
            &source, FAMILY, &group_key
        )
        .unwrap()
    );
    let mut tampered = one.records;
    tampered[0].key[0] ^= 1;
    assert!(
        busbar_migrations::legacy::projection::verify_marker(&source, FAMILY, &tampered[0])
            .is_err()
    );
    let both = source.page(&snapshot, &family(), 0, bounds).await.unwrap();
    assert_eq!(both.records.len(), 2);
    assert!(both.complete);
    assert!(matches!(
        source.page(&snapshot, &family(), 1, bounds).await,
        Err(Error::Corrupt)
    ));
    let bounds = Bounds {
        items: 4,
        bytes: 4096,
    };
    let format = source.identity().format;
    let edge = Edge {
        id: [3; 16],
        source: format,
        target: format,
        code_digest: [4; 32],
        preconditions_digest: [5; 32],
        verification_rule_digest: [6; 32],
        bounds,
        families: vec![family()],
    };
    let transform: Arc<dyn Transform> = Arc::new(Expands(edge, false));
    let source = source.with_output_budget(&transform).unwrap();
    let both = source.page(&snapshot, &family(), 0, bounds).await.unwrap();
    assert_eq!(
        both.records.len(),
        2,
        "disjoint projected groups batch together"
    );
    assert!(both.complete);
    let first = source
        .page(
            &snapshot,
            &family(),
            0,
            Bounds {
                items: 3,
                bytes: 4096,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        first.records.len(),
        1,
        "target output count limits batching"
    );
    assert_eq!(first.next, 2);
    let mut forged = family();
    forged.target_namespace = [7; 16];
    assert!(matches!(
        source.page(&snapshot, &forged, 0, bounds).await,
        Err(Error::IdentityMismatch)
    ));
}
#[tokio::test]
async fn content_snapshot_binding_and_complete_group_byte_bounds_fail_closed() {
    let source = ArchiveSource::open(archive(), Arc::new(Groups), 8192, [1, 5, 5]).unwrap();
    let snapshot = source.snapshot();
    assert_eq!(source.identity().artifact_digest, snapshot.content_digest);
    let mut changed = snapshot.clone();
    changed.coverage_digest[0] ^= 1;
    assert!(matches!(
        source
            .page(
                &changed,
                &family(),
                0,
                Bounds {
                    items: 3,
                    bytes: 4096
                }
            )
            .await,
        Err(Error::IdentityMismatch)
    ));
    assert!(matches!(
        source
            .page(&snapshot, &family(), 0, Bounds { items: 3, bytes: 1 })
            .await,
        Err(Error::Bounds)
    ));
}
#[test]
fn protected_group_index_has_an_explicit_independent_allocation_budget() {
    assert!(matches!(
        ArchiveSource::open(archive(), Arc::new(Groups), 1, [1, 5, 5]),
        Err(Error::Bounds)
    ));
}

#[tokio::test]
async fn physical_pages_cover_each_original_row_once_independent_of_group_size() {
    let source = ArchiveSource::open(archive(), Arc::new(Groups), 8192, [1, 5, 5]).unwrap();
    let mut physical = family();
    physical.id = busbar_migrations::legacy::projection::PHYSICAL;
    let snapshot = source.snapshot();
    let bounds = Bounds {
        items: 2,
        bytes: 4096,
    };
    let first = source.page(&snapshot, &physical, 0, bounds).await.unwrap();
    assert_eq!(first.records.len(), 2);
    assert_eq!(first.next, 2);
    assert!(!first.complete);
    let last = source
        .page(&snapshot, &physical, first.next, bounds)
        .await
        .unwrap();
    assert_eq!(last.records.len(), 1);
    assert_eq!(last.next, 3);
    assert!(last.complete);
    assert!(first
        .records
        .iter()
        .chain(&last.records)
        .all(|row| row.preserve_exact));
    assert_ne!(first.records[0].key, first.records[1].key);
    assert_ne!(first.records[0].key, last.records[0].key);
}

#[tokio::test]
async fn overlapping_valid_groups_end_the_page_before_the_second_marker() {
    let source = ArchiveSource::open(archive(), Arc::new(Groups), 8192, [1, 5, 5]).unwrap();
    let bounds = Bounds {
        items: 8,
        bytes: 4096,
    };
    let format = source.identity().format;
    let edge = Edge {
        id: [3; 16],
        source: format,
        target: format,
        code_digest: [4; 32],
        preconditions_digest: [5; 32],
        verification_rule_digest: [6; 32],
        bounds,
        families: vec![family()],
    };
    let transform: Arc<dyn Transform> = Arc::new(Expands(edge, true));
    source
        .bind_output_budget(Arc::downgrade(&transform))
        .unwrap();
    source
        .bind_output_budget(Arc::downgrade(&transform))
        .unwrap();
    let snapshot = source.snapshot();
    let first = source.page(&snapshot, &family(), 0, bounds).await.unwrap();
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.next, 2);
    let last = source
        .page(&snapshot, &family(), first.next, bounds)
        .await
        .unwrap();
    assert_eq!(last.records.len(), 1);
    assert!(last.complete);
    let forged = Record {
        key: first.records[0].key.clone(),
        value: busbar_migrations::legacy::projection::encode_marker(
            &Secret::new(first.records[0].key.clone()),
            [9; 32],
        )
        .unwrap(),
        preserve_exact: false,
    };
    assert!(matches!(
        busbar_migrations::legacy::projection::verify_marker(&source, FAMILY, &forged),
        Err(Error::IdentityMismatch)
    ));
    drop(transform);
    assert!(matches!(
        source.page(&snapshot, &family(), 0, bounds).await,
        Err(Error::MissingCapability)
    ));
}

#[test]
fn immutable_inventory_remains_original_and_frame_reread_rejects_tampering() {
    use busbar_migrations::legacy::projection::ProjectionSource;
    let (bytes, limits) = archive_bytes();
    let backing = Arc::new(Mutex::new(Cursor::new(bytes)));
    let verified = archive::read(SharedRead(backing.clone()), limits).unwrap();
    let source = ArchiveSource::open(verified, Arc::new(Groups), 8192, [1, 5, 5]).unwrap();
    let key = Secret::new(1i64.to_be_bytes().to_vec());
    let original = source.inventory_digest(FAMILY, &key).unwrap();
    {
        let mut backing = backing.lock().unwrap();
        let bytes = backing.get_mut();
        let offset = bytes
            .windows(b"opaque-private-value".len())
            .position(|part| part == b"opaque-private-value")
            .unwrap();
        bytes[offset] ^= 1;
    }
    assert_eq!(source.inventory_digest(FAMILY, &key).unwrap(), original);
    assert!(matches!(
        source.visit(FAMILY, &key, 4096, &mut |_| Ok(())),
        Err(Error::Corrupt)
    ));
}
