//! A data worker's stripe: each worker id picks its own stripe, an out-of-range id clamps to the
//! last one, and a thread that never set an id shares the last (fallback) stripe.

#[test]
fn worker_ids_index_distinct_stripes_and_unset_falls_back() {
    let stripe_for = |id: Option<usize>, stripes: usize| {
        std::thread::spawn(move || {
            if let Some(i) = id {
                super::set_worker_id(i);
            }
            super::worker_stripe(stripes)
        })
        .join()
        .unwrap()
    };
    assert_eq!(stripe_for(Some(0), 4), 0);
    assert_eq!(stripe_for(Some(1), 4), 1);
    assert_eq!(stripe_for(Some(2), 4), 2);
    assert_eq!(
        stripe_for(Some(9), 4),
        3,
        "an out-of-range id clamps to the last stripe"
    );
    assert_eq!(
        stripe_for(None, 4),
        3,
        "an unset id falls back to the last stripe"
    );
}
