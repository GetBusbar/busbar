//! ONE PARALLEL MAP FOR THE GATES' READ-ONLY SCANS.
//!
//! A gate that judges each file (or each rule) on its own inputs alone can judge them on every
//! core, provided the answer is put back together in the order a serial loop would have produced
//! it: the rows a gate prints are read by people and diffed by tools, so a verdict whose text
//! depended on thread scheduling would be a verdict nobody could compare. [`par_map`] is that
//! contract, once, for every gate that uses it.

/// `f` over every item, across the cores, with the results in the items' order.
///
/// Items are handed out one at a time from a shared cursor, so a few large items cannot pile onto
/// one worker. Workers get a 16 MiB stack: several scans drive `rx`, whose general repeat path
/// recurses once per iteration, and the main thread they replace had 8 MiB. A panic in `f` is
/// re-raised on the caller with its own payload, exactly as the serial loop would have raised it.
pub fn par_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(items.len());
    if workers <= 1 {
        return items.iter().map(f).collect();
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut out: Vec<(usize, R)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                std::thread::Builder::new()
                    .stack_size(16 * 1024 * 1024)
                    .spawn_scoped(scope, || {
                        let mut mine = Vec::new();
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let Some(item) = items.get(i) else {
                                break;
                            };
                            mine.push((i, f(item)));
                        }
                        mine
                    })
                    .expect("spawn a scan worker thread")
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| match h.join() {
                Ok(mine) => mine,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    });
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}
