//! The direct `mallctl` calls behave as `tikv-jemalloc-ctl`'s did: same controls, same value
//! types, same refusals and the same error text. The kernel's test build runs on jemalloc.

use super::*;

#[test]
fn the_controls_the_binary_tunes_read_with_their_types() {
    let narenas: u32 = read(c"arenas.narenas").expect("arenas.narenas is a u32");
    assert!(narenas >= 1, "jemalloc has at least one arena");
    let decay: isize = read(c"opt.dirty_decay_ms").expect("opt.dirty_decay_ms is an ssize_t");
    assert!(
        decay >= -1,
        "a decay is -1 (never) or a millisecond count: {decay}"
    );
}

#[test]
fn background_thread_round_trips_where_jemalloc_supports_it() {
    // The boot writes `background_thread` and reads it back, and falls back to its own idle purge
    // when jemalloc has no background-thread support (macOS): the control is then refused.
    match read::<bool>(c"background_thread") {
        Ok(before) => {
            write(c"background_thread", before).expect("background_thread is writable");
            assert_eq!(read::<bool>(c"background_thread").ok(), Some(before));
        }
        Err(error) => assert!(
            !cfg!(target_os = "linux"),
            "Linux jemalloc has background threads, yet background_thread is refused: {error}"
        ),
    }
}

#[test]
fn an_arena_decay_round_trips_through_a_write() {
    let name = c"arena.0.dirty_decay_ms";
    let prior: isize = read(name).expect("arena 0 exists");
    write(name, 0isize).expect("the decay is writable");
    assert_eq!(read::<isize>(name).ok(), Some(0));
    write(name, prior).expect("the prior decay is restored");
    assert_eq!(read::<isize>(name).ok(), Some(prior));
}

#[test]
fn an_unknown_control_is_refused_with_jemallocs_enoent_text() {
    let error = read::<u32>(c"no.such.control").expect_err("unknown names are refused");
    assert_eq!(error.code(), libc::ENOENT);
    assert_eq!(
        error.to_string(),
        "`name` or `mib` specifies an unknown/invalid value."
    );
    let error = write(c"no.such.control", 1u32).expect_err("unknown names are refused");
    assert_eq!(error.code(), libc::ENOENT);
}

#[test]
fn a_value_of_the_wrong_width_is_refused_not_misread() {
    // arenas.narenas is 4 bytes; jemalloc refuses an 8-byte read with EINVAL.
    let error = read::<u64>(c"arenas.narenas").expect_err("a width mismatch is refused");
    assert_eq!(error.code(), libc::EINVAL);
    assert!(error
        .to_string()
        .starts_with("`newp` is not `NULL`, and `newlen` is too large or too small."));
}

#[test]
fn a_read_only_control_refuses_a_write_with_eperm() {
    let error = write(c"arenas.narenas", 1u32).expect_err("arenas.narenas is read-only");
    assert_eq!(error.code(), libc::EPERM);
    assert_eq!(
        error.to_string(),
        "Attempt to read or write `void` value, or attempt to write read-only value."
    );
}

#[test]
fn every_error_text_is_tikv_jemalloc_ctls() {
    for (code, text) in [
        (libc::EAGAIN, "A memory allocation failure occurred."),
        (
            libc::EFAULT,
            "An interface with side effects failed in some way not directly related to `mallctl*()` read/write processing.",
        ),
        (
            libc::EINVAL,
            "`newp` is not `NULL`, and `newlen` is too large or too small. Alternatively, `*oldlenp` is too large or too small; in this case as much data as possible are read despite the error.",
        ),
        (12345, "Unknown error code: \"12345\"."),
    ] {
        assert_eq!(Error(code).to_string(), text);
        assert_eq!(format!("{:?}", Error(code)), text);
    }
}

#[test]
fn the_thread_counters_follow_this_threads_allocations_only() {
    let allocated = thread_allocated().expect("thread.allocatedp is available");
    let deallocated = thread_deallocated().expect("thread.deallocatedp is available");
    let (a0, d0) = (allocated.get(), deallocated.get());
    let buffer = std::hint::black_box(vec![0u8; 1 << 20]);
    let a1 = allocated.get();
    assert!(
        a1 >= a0 + (1 << 20),
        "a 1 MiB allocation is counted: {a0} -> {a1}"
    );
    drop(buffer);
    assert!(
        deallocated.get() >= d0 + (1 << 20),
        "its release is counted"
    );

    let before = allocated.get();
    std::thread::spawn(|| std::hint::black_box(vec![0u8; 1 << 20]).len())
        .join()
        .expect("the other thread allocates");
    assert!(
        allocated.get() - before < 1 << 20,
        "another thread's allocation is not this thread's"
    );
}
