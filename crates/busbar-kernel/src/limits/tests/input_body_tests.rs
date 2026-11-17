// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::body::Body;
use bytes::Bytes;
use futures::{stream, StreamExt};

use super::{gather, GatherError};
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};

#[tokio::test]
async fn opaque_source_and_gathered_backing_are_independently_charged() {
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let source = request.copy_input(b"payload").unwrap().into_bytes();
    let gathered = gather(Body::from(source.clone()), &request, 7).await.unwrap();
    assert_eq!(gathered.as_ref(), b"payload");
    assert_eq!(budget.used(), (14, 14));
    let tail = gathered.slice(3..);
    drop(source);
    drop(gathered);
    drop(request);
    assert_eq!(budget.used(), (7, 7));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(tail);
    assert_eq!(budget.used(), (0, 0));
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn gather_refuses_independent_copy_without_releasing_source_credit() {
    let budget = ProcessAdmission::with_limits(2, 10, 2);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let source = request.copy_input(b"payload").unwrap().into_bytes();
    assert!(matches!(
        gather(Body::from(source.clone()), &request, 7).await,
        Err(GatherError::Capacity(_))
    ));
    assert_eq!(source.as_ref(), b"payload");
    assert_eq!(budget.used(), (7, 7));
    drop(source);
    assert_eq!(budget.used(), (0, 0));
}

#[tokio::test]
async fn gather_cancellation_releases_partial_output_without_restarting_reader() {
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let source = request.copy_input(b"part").unwrap().into_bytes();
    let input = stream::iter([Ok::<_, std::io::Error>(source)])
        .chain(stream::pending());
    let mut gathered = Box::pin(gather(Body::from_stream(input), &request, 16));
    assert!(futures::poll!(&mut gathered).is_pending());
    assert_eq!(budget.used(), (4, 4));
    assert!(budget.try_enter(AdmissionClass::Data).is_err());
    drop(gathered);
    assert_eq!(budget.used(), (0, 0));
    drop(request);
    assert!(budget.try_enter(AdmissionClass::Data).is_ok());
}

#[tokio::test]
async fn gather_preserves_message_ceiling_and_reclaims_on_read_error() {
    let budget = ProcessAdmission::with_limits(2, 64, 8);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let pieces = stream::iter([
        Ok::<_, std::io::Error>(Bytes::from_static(b"ab")),
        Ok(Bytes::from_static(b"cd")),
    ]);
    assert!(matches!(gather(Body::from_stream(pieces), &request, 3).await, Err(GatherError::TooLarge)));
    assert_eq!(budget.used(), (0, 0));
    let pieces = stream::iter([
        Ok(Bytes::from_static(b"ab")),
        Err(std::io::Error::other("reader failed")),
    ]);
    assert!(matches!(gather(Body::from_stream(pieces), &request, 3).await, Err(GatherError::Body(_))));
    assert_eq!(budget.used(), (0, 0));
    assert!(gather(Body::empty(), &request, 0).await.unwrap().is_empty());
}
