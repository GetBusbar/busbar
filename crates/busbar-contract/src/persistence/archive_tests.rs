use super::*;
use crate::persistence::legacy_row::{self, Cell};
use std::io::Cursor;

crate::own_seal!(Own);
fn limits() -> Limits {
    Limits {
        frame_bytes: 4096,
        total_bytes: 65536,
        rows: 16,
        tables: 2,
        columns: 8,
        index_bytes: 8192,
    }
}
fn header() -> Header {
    Header {
        owner: *b"legacy.sqlite.v1",
        physical: 6,
        catalogue_digest: digest(b"native catalogue"),
        native_anchor_digest: [0; 32],
        capture: None,
        tables: vec![Table {
            name: "credentials".into(),
            columns: ["z", "a", "r", "t", "b"].map(str::to_string).to_vec(),
            native_layout: b"exact ordered native type declarations".to_vec(),
        }],
    }
}
fn row() -> crate::Secret<Vec<u8>, Own> {
    legacy_row::encode(
        &[
            Cell::Null,
            Cell::Integer(i64::MIN),
            Cell::RealBits(1 << 63),
            Cell::Text(b"\xff\0"),
            Cell::Blob(b"private-envelope\0"),
        ],
        4096,
    )
    .unwrap()
}
fn artifact() -> Vec<u8> {
    let row = row();
    let mut writer = Writer::new(Vec::new(), header(), limits()).unwrap();
    writer
        .write_row(0, b"native-key", row.expose_own(&Own::here()))
        .unwrap();
    writer.finish().unwrap().0
}
#[test]
fn streaming_archive_keeps_original_types_order_and_full_artifact_identity() {
    let bytes = artifact();
    let mut verified = read(Cursor::new(&bytes), limits()).unwrap();
    assert_eq!(verified.summary().digest, digest(&bytes));
    assert_eq!(verified.summary().bytes, bytes.len() as u64);
    assert_eq!(verified.header().tables[0].columns[0], "z");
    assert_eq!(verified.find_native(0, b"native-key").unwrap(), Some(0));
    assert_eq!(verified.find_native(0, b"missing").unwrap(), None);
    assert!(verified.find_native(1, b"native-key").is_err());
    let mut snapshot_only = header();
    snapshot_only.native_anchor_digest = digest(b"native instance database");
    snapshot_only.capture = Some(CaptureFence {
        writer_inventory_sha256: [1; 32],
        enforcement_policy_sha256: [2; 32],
        prefence_observation_sha256: [3; 32],
    });
    assert!(matches!(
        Writer::new(Vec::new(), snapshot_only.clone(), limits())
            .unwrap()
            .finish(),
        Err(Error::Integrity)
    ));
    assert!(matches!(
        Writer::new(Vec::new(), snapshot_only.clone(), limits())
            .unwrap()
            .finish_captured([0; 32]),
        Err(Error::Integrity)
    ));
    assert!(matches!(
        Writer::new(Vec::new(), header(), limits())
            .unwrap()
            .finish_captured([4; 32]),
        Err(Error::Integrity)
    ));
    let expected_content = Writer::new(Vec::new(), snapshot_only.clone(), limits())
        .unwrap()
        .content_digest();
    let (snapshot_bytes, snapshot_summary) = Writer::new(Vec::new(), snapshot_only, limits())
        .unwrap()
        .finish_captured([4; 32])
        .unwrap();
    assert_eq!(snapshot_summary.content_digest, expected_content);
    let snapshot_archive = read(Cursor::new(snapshot_bytes), limits()).unwrap();
    assert_eq!(
        snapshot_archive.header().native_anchor_digest,
        digest(b"native instance database")
    );
    assert_eq!(
        snapshot_archive.summary().post_observation_sha256,
        Some([4; 32])
    );
    assert_eq!(
        snapshot_archive.summary().content_digest,
        snapshot_summary.content_digest
    );
    assert_ne!(
        snapshot_summary.layout_digest,
        verified.summary().layout_digest
    );
    let row = verified.read_row(0).unwrap();
    assert_eq!(row.native_key.0, b"native-key");
    let cells: Vec<_> = legacy_row::Row::decode(&row.value.0)
        .unwrap()
        .cells()
        .collect();
    assert_eq!(
        cells,
        vec![
            Cell::Null,
            Cell::Integer(i64::MIN),
            Cell::RealBits(1 << 63),
            Cell::Text(b"\xff\0"),
            Cell::Blob(b"private-envelope\0")
        ]
    );
    let debug = format!("{row:?}");
    assert!(!debug.contains("native-key") && !debug.contains("private-envelope"));
}
#[test]
fn incomplete_extra_corrupt_and_unknown_frames_never_admit_a_source() {
    let bytes = artifact();
    for end in 0..bytes.len() {
        assert!(
            read(Cursor::new(&bytes[..end]), limits()).is_err(),
            "accepted prefix {end}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(read(Cursor::new(extra), limits()).is_err());
    let mut corrupt = bytes.clone();
    let corrupt_prefix = corrupt.len() - 2;
    corrupt[corrupt_prefix] ^= 1;
    assert!(matches!(
        read(Cursor::new(corrupt), limits()),
        Err(Error::Integrity)
    ));
    let header_len = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
    let mut unknown = bytes;
    unknown[20 + header_len] = 2;
    assert!(matches!(
        read(Cursor::new(unknown), limits()),
        Err(Error::Malformed)
    ));
}
#[test]
fn duplicate_native_identity_and_column_names_are_refused() {
    let raw = row();
    let mut writer = Writer::new(Vec::new(), header(), limits()).unwrap();
    writer
        .write_row(0, b"same", raw.expose_own(&Own::here()))
        .unwrap();
    writer
        .write_row(0, b"same", raw.expose_own(&Own::here()))
        .unwrap();
    let bytes = writer.finish().unwrap().0;
    assert!(matches!(
        read(Cursor::new(bytes), limits()),
        Err(Error::Integrity)
    ));
    let mut h = header();
    h.tables[0].columns[1] = "z".into();
    assert!(matches!(
        Writer::new(Vec::new(), h, limits()),
        Err(Error::Malformed)
    ));
}
#[test]
fn explicit_frame_aggregate_and_index_budgets_refuse_before_rows_escape() {
    let bytes = artifact();
    let mut bound = limits();
    bound.frame_bytes = 32;
    assert!(read(Cursor::new(&bytes), bound).is_err());
    let mut bound = limits();
    bound.total_bytes = bytes.len() as u64 - 1;
    assert!(matches!(
        read(Cursor::new(&bytes), bound),
        Err(Error::Budget)
    ));
    let mut bound = limits();
    bound.index_bytes = 1;
    assert!(matches!(
        read(Cursor::new(&bytes), bound),
        Err(Error::Budget)
    ));
    let mut bound = limits();
    bound.rows = 0;
    assert!(read(Cursor::new(&bytes), bound).is_err());
}
#[test]
fn seeked_row_cannot_change_after_the_full_stream_was_verified() {
    use std::sync::{Arc, Mutex};
    struct Shared(Arc<Mutex<Cursor<Vec<u8>>>>);
    impl Read for Shared {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().read(out)
        }
    }
    impl Seek for Shared {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.0.lock().unwrap().seek(pos)
        }
    }
    let state = Arc::new(Mutex::new(Cursor::new(artifact())));
    let mut verified = read(Shared(state.clone()), limits()).unwrap();
    let at = verified.index[0].offset as usize + 4 + 8;
    state.lock().unwrap().get_mut()[at] ^= 1;
    assert!(matches!(verified.read_row(0), Err(Error::Integrity)));
}
