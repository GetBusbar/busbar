use super::*;

/// The transaction body is SYNCHRONOUS and its plan is applied by `config_transaction` alone: a body
/// that declares no plan mutates nothing (fail-closed), and the value it returns is passed through.
#[tokio::test]
async fn readonly_txn_swaps_nothing() {
    let handle = Arc::new(AppHandle::new(crate::test_support::TestApp::new().build()));
    let before = handle.load().config_version;
    let v: u64 = config_transaction(&handle, |txn| Ok(txn.done(txn.app().config_version)))
        .await
        .expect("read-only txn succeeds");
    assert_eq!(v, before);
    assert_eq!(handle.load().config_version, before, "no plan ⇒ no swap");
}
