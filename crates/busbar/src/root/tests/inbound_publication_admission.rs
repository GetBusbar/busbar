// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::num::NonZeroU64;
use std::sync::Arc;

use busbar_kernel::state::{AdmissionRefusal, AppHandle, InvocationId};

#[tokio::test]
async fn publication_before_final_admission_refuses_without_running_policy() {
    let original = super::app(false).await.0;
    let next = Arc::new((*original).clone());
    let handle = AppHandle::new(Arc::clone(&original));
    handle.swap(Arc::clone(&next)).await;
    let invocation =
        InvocationId::from_request_id(NonZeroU64::new(original.next_request_id()).unwrap());
    let mut called = false;
    let result = handle.admit_current(&original, invocation, |_| {
        called = true;
        Ok::<_, ()>(())
    });
    assert!(matches!(result, Err(AdmissionRefusal::StaleGeneration)));
    assert!(
        !called,
        "a stale request never reaches final policy or replay"
    );
    assert!(Arc::ptr_eq(&handle.load(), &next));
}

#[tokio::test]
async fn final_admission_retains_the_original_generation_across_publication() {
    let original = super::app(false).await.0;
    let next = Arc::new((*original).clone());
    let handle = AppHandle::new(Arc::clone(&original));
    let invocation =
        InvocationId::from_request_id(NonZeroU64::new(original.next_request_id()).unwrap());
    let lease = handle
        .admit_current(&original, invocation, |_| Ok::<_, ()>(()))
        .unwrap();
    handle.swap(Arc::clone(&next)).await;
    assert!(Arc::ptr_eq(lease.generation(), &original));
    assert_eq!(lease.invocation(), invocation);
    assert!(Arc::ptr_eq(&handle.load(), &next));
    let denied = handle.admit_current(&next, invocation, |_| Err("denied"));
    assert!(matches!(denied, Err(AdmissionRefusal::Policy("denied"))));
}
