// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connection pool: the SSRF check runs before a client exists, and the cache key is the PINNED
//! address so a rebinding answer cannot be served out of it.

use crate::mcp::client::pool::McpConnectionPool;
use crate::mcp::client::ssrf::{SsrfPolicy, SsrfRefusal};
use std::time::Duration;

fn private_ok() -> SsrfPolicy {
    SsrfPolicy {
        allow_private: true,
    }
}

#[tokio::test]
async fn a_refused_destination_never_produces_a_client() {
    let pool = McpConnectionPool::new();
    let refused = [
        "https://127.0.0.1/mcp",
        "https://169.254.169.254/mcp",
        "file:///etc/passwd",
        "https://0x7f000001/mcp",
    ];
    assert_eq!(refused.len(), 4);
    for url in refused {
        assert!(
            pool.client_for(url, SsrfPolicy::default(), Duration::from_secs(5))
                .await
                .is_err(),
            "`{url}` must not yield a client"
        );
    }
    // THE FLOOR that makes the above non-vacuous: nothing entered the pool, and a permitted
    // destination DOES enter it.
    assert_eq!(
        pool.len(),
        0,
        "a refused destination must leave no client behind"
    );
    pool.client_for(
        "http://127.0.0.1:9/mcp",
        private_ok(),
        Duration::from_secs(5),
    )
    .await
    .expect("an opted-in private destination yields a client");
    assert_eq!(pool.len(), 1);
}

#[tokio::test]
async fn a_repeated_destination_reuses_one_client() {
    let pool = McpConnectionPool::new();
    for _ in 0..5 {
        pool.client_for(
            "http://127.0.0.1:9/mcp",
            private_ok(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    }
    assert_eq!(pool.len(), 1, "the pool must reuse, not accumulate");
}

/// THE KEY IS THE PINNED ADDRESS, and the two URLs below share a HOST so that the address is the
/// only thing telling them apart. A key that dropped the address would collapse them into one entry
/// and serve the second destination out of a client built for the first — the cache laundering an
/// address the check never saw, which is the whole hazard.
#[tokio::test]
async fn the_pool_key_is_the_pinned_address_and_not_just_the_host() {
    let pool = McpConnectionPool::new();
    let (_, a) = pool
        .client_for(
            "http://127.0.0.1:9/mcp",
            private_ok(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let (_, b) = pool
        .client_for(
            "http://127.0.0.1:10/mcp",
            private_ok(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(
        a.host(),
        b.host(),
        "the host must be identical for this to prove anything"
    );
    // `socket_addr()` IS the second half of the pool key. Asserting on it rather than on the bare
    // IP is the point of this test: two upstreams on one host and two ports must not share a
    // pinned client, and a key that forgot the port would.
    assert_ne!(a.socket_addr(), b.socket_addr());
    assert_eq!(pool.len(), 2, "two pinned addresses must be two entries");
}

/// Two different hosts are two entries as well, which is the easy half.
#[tokio::test]
async fn two_hosts_are_two_entries() {
    let pool = McpConnectionPool::new();
    pool.client_for(
        "http://127.0.0.1:9/mcp",
        private_ok(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    pool.client_for(
        "http://127.0.0.2:9/mcp",
        private_ok(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(pool.len(), 2);
}

/// The pinned target returned alongside the client carries the address that passed, so the caller
/// cannot be handed a client for one address and a target describing another.
#[tokio::test]
async fn the_returned_target_is_the_one_that_passed_the_check() {
    let pool = McpConnectionPool::new();
    let (_client, target) = pool
        .client_for(
            "http://127.0.0.1:9/mcp",
            private_ok(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(target.socket_addr().to_string(), "127.0.0.1:9");
    assert_eq!(target.addr().to_string(), "127.0.0.1");
    assert_eq!(target.host(), "127.0.0.1");
}

#[tokio::test]
async fn an_unresolvable_host_is_reported_as_such_rather_than_as_a_connection_error() {
    let pool = McpConnectionPool::new();
    let err = pool
        .client_for(
            "https://this-name-must-not-resolve.invalid/mcp",
            SsrfPolicy::default(),
            Duration::from_secs(5),
        )
        .await
        .expect_err("the `.invalid` TLD is reserved and never resolves");
    assert!(
        matches!(err, SsrfRefusal::Unresolvable { .. }),
        "got {err:?}"
    );
}
