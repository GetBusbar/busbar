//! jemalloc's `mallctl` control interface, called directly through `tikv-jemalloc-sys`.
//!
//! The binary tunes its allocator at boot (the background purge thread, the idle arena purge
//! fallback) and the allocation tests read jemalloc's per-thread counters. This used to go through
//! `tikv-jemalloc-ctl`, whose only remaining dependency on an unmaintained crate (`paste`, a
//! proc-macro it uses to generate one accessor per control name) has no fixed release. The handful
//! of controls busbar reads and writes are called here with the same `mallctl(3)` calls, the same
//! value types and the same error texts, so behaviour is unchanged.
//!
//! The FFI is confined to [`read`], [`write`] and [`ThreadCounter::get`]. Each control is named by
//! a `&CStr`, so the name is NUL-terminated by construction, and values are limited to the plain
//! integer and boolean types [`Value`] admits, for which every bit pattern jemalloc writes is valid.

use std::ffi::{c_void, CStr};
use std::fmt;
use std::marker::PhantomData;

/// A `mallctl` failure: jemalloc's error number, shown with the text `tikv-jemalloc-ctl` printed.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Error(i32);

impl Error {
    /// The `errno` value `mallctl` returned.
    #[must_use]
    pub fn code(self) -> i32 {
        self.0
    }
}

fn description(code: i32) -> Option<&'static str> {
    match code {
        libc::EINVAL => Some(
            "`newp` is not `NULL`, and `newlen` is too large or too small. Alternatively, \
             `*oldlenp` is too large or too small; in this case as much data as possible are read \
             despite the error.",
        ),
        libc::ENOENT => Some("`name` or `mib` specifies an unknown/invalid value."),
        libc::EPERM => {
            Some("Attempt to read or write `void` value, or attempt to write read-only value.")
        }
        libc::EAGAIN => Some("A memory allocation failure occurred."),
        libc::EFAULT => Some(
            "An interface with side effects failed in some way not directly related to \
             `mallctl*()` read/write processing.",
        ),
        _ => None,
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match description(self.0) {
            Some(m) => write!(f, "{m}"),
            None => write!(f, "Unknown error code: \"{}\".", self.0),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

mod sealed {
    pub trait Sealed {}
}

/// A control value type: a plain integer or `bool`, valid for any value jemalloc stores.
pub trait Value: Copy + Default + sealed::Sealed {}

macro_rules! values {
    ($($t:ty),*) => {
        $(impl sealed::Sealed for $t {} impl Value for $t {})*
    };
}
values!(bool, u32, u64, usize, isize);

fn check(code: i32) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        code => Err(Error(code)),
    }
}

/// Reads the control `name` (`mallctl(name, &old, &len, NULL, 0)`).
///
/// # Errors
/// jemalloc refused the read (unknown name, wrong value size, ...).
pub fn read<T: Value>(name: &CStr) -> Result<T, Error> {
    let mut value = T::default();
    let mut len = std::mem::size_of::<T>();
    // SAFETY: `name` is a NUL-terminated C string; `value` is a live, writable `T` of `len` bytes,
    // and every bit pattern is a valid `T` (`Value` admits only integers and `bool`, which
    // jemalloc stores as 0 or 1); no new value is passed.
    let code = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr(),
            (&raw mut value).cast::<c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    check(code)?;
    if len != std::mem::size_of::<T>() {
        return Err(Error(libc::EINVAL));
    }
    Ok(value)
}

/// Writes `value` to the control `name` (`mallctl(name, NULL, NULL, &new, sizeof new)`).
///
/// # Errors
/// jemalloc refused the write (unknown or read-only name, wrong value size, ...).
pub fn write<T: Value>(name: &CStr, value: T) -> Result<(), Error> {
    let mut value = value;
    // SAFETY: `name` is a NUL-terminated C string; `value` is a live `T` of the length passed, and
    // jemalloc only reads it; no old value is requested.
    let code = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            (&raw mut value).cast::<c_void>(),
            std::mem::size_of::<T>(),
        )
    };
    check(code)
}

/// One of the calling thread's cumulative allocation counters (`thread.allocatedp` /
/// `thread.deallocatedp`): jemalloc hands out a pointer into its thread-local state, read here
/// without a `mallctl` call each time. Not `Send`: the pointer is only meaningful on the thread
/// that asked for it.
pub struct ThreadCounter {
    counter: *const u64,
    _thread_bound: PhantomData<*const u64>,
}

impl ThreadCounter {
    /// The counter's current value.
    #[must_use]
    pub fn get(&self) -> u64 {
        // SAFETY: jemalloc returned this non-null pointer into the current thread's state (the type
        // is not `Send`), which stays valid for the thread's lifetime. Volatile: jemalloc updates
        // it behind the compiler's back on every allocation.
        unsafe { self.counter.read_volatile() }
    }
}

fn thread_counter(name: &CStr) -> Result<ThreadCounter, Error> {
    let mut counter: *mut u64 = std::ptr::null_mut();
    let mut len = std::mem::size_of::<*mut u64>();
    // SAFETY: `name` is a NUL-terminated C string; `counter` is a live, writable pointer-sized slot
    // of `len` bytes; no new value is passed.
    let code = unsafe {
        tikv_jemalloc_sys::mallctl(
            name.as_ptr(),
            (&raw mut counter).cast::<c_void>(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    check(code)?;
    if len != std::mem::size_of::<*mut u64>() || counter.is_null() {
        return Err(Error(libc::EINVAL));
    }
    Ok(ThreadCounter {
        counter,
        _thread_bound: PhantomData,
    })
}

/// The calling thread's total bytes ever allocated (`thread.allocatedp`).
///
/// # Errors
/// jemalloc was built without per-thread statistics.
pub fn thread_allocated() -> Result<ThreadCounter, Error> {
    thread_counter(c"thread.allocatedp")
}

/// The calling thread's total bytes ever deallocated (`thread.deallocatedp`).
///
/// # Errors
/// jemalloc was built without per-thread statistics.
pub fn thread_deallocated() -> Result<ThreadCounter, Error> {
    thread_counter(c"thread.deallocatedp")
}

#[cfg(test)]
#[path = "tests/mallctl_tests.rs"]
mod tests;
