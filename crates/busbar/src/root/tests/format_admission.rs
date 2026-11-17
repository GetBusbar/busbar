// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! #319 r4 §5 and §13 ("production root S6 reachability"): through the gateway's own admission
//! path, an older record format reaches the conversion before ordinary admission, every row is
//! converted, the final publication admits ordinarily, and a process of the old epoch is fenced.
//! The step 0 -> 1 is synthetic (the kernel writes format 1); the production chain stays empty.

use busbar_contract::persistence::{witness, NamespaceId};
use busbar_contract::secure::SecureVec;
use busbar_migrate::records::{Candidate, Committed, RecordStep, RecordStore, Refusal};

use super::{Store, AUDIT_NS};

const DATA_NS: NamespaceId = NamespaceId(*b"test.format319\0\0");

fn to_one(_: NamespaceId, _: &[u8], value: &[u8]) -> Result<SecureVec, Refusal> {
    let mut out = b"1:".to_vec();
    out.extend_from_slice(value);
    Ok(SecureVec::from(out))
}

static ZERO_TO_ONE: [RecordStep; 1] = [RecordStep {
    from: 0,
    namespaces: &[DATA_NS],
    convert: to_one,
}];

/// A runtime that drives the store while the test thread blocks, as the boot's runtime drives it
/// while the conversion runs on a blocking thread.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn an_older_format_is_converted_before_ordinary_admission() {
    let rt = runtime();
    let backend = rt.block_on(crate::root::real_store::native_backend());
    let old = Store::new(
        rt.block_on(crate::root::real_store::core_over(backend.clone())),
        rt.handle().clone(),
    );
    let manifest = busbar_kernel::persistence::import_target::target::manifest_address();
    let ns = NamespaceId(manifest.namespace);
    let mut bytes = old.read(ns, &manifest.key).unwrap().unwrap().to_vec();
    for at in [8, 12, 16, 20] {
        bytes[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
    }
    let mut c = Candidate::default();
    c.put
        .push((ns, manifest.key.clone(), SecureVec::from(bytes)));
    c.delete
        .push((witness::BIRTH_NAMESPACE, witness::BIRTH_KEY.to_vec()));
    for key in 0..5u8 {
        c.put
            .push((DATA_NS, vec![key], SecureVec::from(b"v".to_vec())));
    }
    assert_eq!(old.commit(c).unwrap(), Committed::Applied);

    // The production chain converts nothing: format 0 is refused before any write.
    assert!(rt
        .block_on(crate::root::boot::admit_format(backend.clone(), false))
        .is_err());
    assert_eq!(
        old.read(ns, b"step").unwrap().map(|cursor| cursor.to_vec()),
        None
    );

    let startup = rt
        .block_on(crate::root::boot::admit_format_with(
            backend,
            false,
            &ZERO_TO_ONE,
        ))
        .expect("converted, published and admitted");
    let now = Store::new(
        startup
            .store()
            .expect("ordinary admission after the publication"),
        rt.handle().clone(),
    );
    let rows = now.scan(DATA_NS, None, 16).unwrap().rows;
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|(_, value)| value.to_vec() == b"1:v"));
    let published = now.read(ns, &manifest.key).unwrap().unwrap().to_vec();
    assert_eq!(published[8..12], 1u32.to_le_bytes());
    assert_eq!(published[72..76], [0; 4]);
    assert_eq!(now.read(ns, b"step").unwrap().map(|c| c.to_vec()), None);
    let evolved = now
        .scan(AUDIT_NS, None, 16)
        .unwrap()
        .rows
        .into_iter()
        .filter(|(key, _)| key.starts_with(b"RECORDS_EVOLVED/"))
        .count();
    assert_eq!(evolved, 1);

    // The process admitted before the conversion is fenced; its row never lands.
    let mut late = Candidate::default();
    late.put
        .push((DATA_NS, vec![9], SecureVec::from(b"late".to_vec())));
    assert_eq!(old.commit(late).unwrap(), Committed::Fenced);
    assert_eq!(now.read(DATA_NS, &[9]).unwrap().map(|v| v.to_vec()), None);
}
