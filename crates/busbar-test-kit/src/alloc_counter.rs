//! A per-thread allocation counter, installed only by binaries that declare [`Counting`] as their
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::rc::Rc;
#[cfg(target_os = "linux")]
use std::{fs::File, os::unix::fs::FileExt};

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
    static PAYLOADS: RefCell<Option<ProbeState>> = const { RefCell::new(None) };
    static READING: Cell<bool> = const { Cell::new(false) };
    static REENTERED: Cell<bool> = const { Cell::new(false) };
    static LIFETIME: Cell<Option<LifetimeState>> = const { Cell::new(None) };
}

#[derive(Clone, Copy)]
struct LifetimeState {
    size: usize,
    address: usize,
    retired: bool,
    observations: AllocationLifetimeObservations,
}

/// Allocator metadata from one exact-size observation window. No allocation contents or addresses
/// are exposed. A unique allocation freed without resizing requires exactly `1`, `1`, and `0`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AllocationLifetimeObservations {
    /// Successful `alloc` or `alloc_zeroed` calls whose `Layout::size()` exactly matched the size.
    /// Multiple matches invalidate attribution, even if the allocator reused the same address.
    pub allocations: u64,
    /// Explicit deallocation of the first matching allocation, at most once.
    pub deallocations: u64,
    /// Reallocation attempts involving the tracked allocation or either selected-size layout.
    /// Any such attempt makes the original-allocation lifetime witness ambiguous.
    pub reallocations: u64,
}

/// A safe, thread-bound metadata observation window over the installed [`Counting`] allocator.
///
/// Start immediately before an otherwise allocation-free operation expected to allocate exactly
/// one buffer of the selected size. Finish after it should release that buffer. Check all three
/// counts: a size match alone cannot identify a buffer if another allocation has the same size.
/// The observer never reads payloads, padding, or spare capacity and allocates no bookkeeping.
/// Allocations and their destruction must occur on this thread to be observed.
#[derive(Debug)]
pub struct AllocationLifetimeProbe {
    _thread_bound: PhantomData<Rc<()>>,
}

impl AllocationLifetimeProbe {
    /// Observe allocations whose complete `Layout::size()` equals `size` on this thread.
    #[must_use]
    pub fn start_exact_size(size: usize) -> Self {
        assert!(
            size != 0,
            "a lifetime probe requires a nonzero allocation size"
        );
        LIFETIME.with(|lifetime| {
            assert!(lifetime.get().is_none(), "one lifetime probe per thread");
            lifetime.set(Some(LifetimeState {
                size,
                address: 0,
                retired: false,
                observations: AllocationLifetimeObservations::default(),
            }));
        });
        Self {
            _thread_bound: PhantomData,
        }
    }

    /// Disarm the observer and return only allocator metadata for this window.
    #[must_use]
    pub fn finish(self) -> AllocationLifetimeObservations {
        LIFETIME.with(|lifetime| lifetime.take().expect("active lifetime probe").observations)
    }
}

impl Drop for AllocationLifetimeProbe {
    fn drop(&mut self) {
        let _ = LIFETIME.try_with(|lifetime| lifetime.set(None));
    }
}

fn lifetime_allocated(address: usize, size: usize) {
    if address == 0 {
        return;
    }
    let _ = LIFETIME.try_with(|lifetime| {
        let Some(mut state) = lifetime.get() else {
            return;
        };
        if size == state.size {
            state.observations.allocations = state.observations.allocations.saturating_add(1);
            if state.observations.allocations == 1 {
                state.address = address;
            }
            lifetime.set(Some(state));
        }
    });
}

fn lifetime_deallocated(address: usize) {
    let _ = LIFETIME.try_with(|lifetime| {
        let Some(mut state) = lifetime.get() else {
            return;
        };
        if state.address != 0 && state.address == address && !state.retired {
            state.retired = true;
            state.observations.deallocations = state.observations.deallocations.saturating_add(1);
            lifetime.set(Some(state));
        }
    });
}

fn lifetime_reallocating(address: usize, old_size: usize, new_size: usize) -> bool {
    LIFETIME
        .try_with(|lifetime| {
            let Some(mut state) = lifetime.get() else {
                return false;
            };
            let tracked = state.address != 0 && state.address == address && !state.retired;
            if tracked || old_size == state.size || new_size == state.size {
                state.observations.reallocations =
                    state.observations.reallocations.saturating_add(1);
                lifetime.set(Some(state));
            }
            tracked
        })
        .unwrap_or(false)
}

fn lifetime_reallocated(old_address: usize, new_address: usize, tracked: bool) {
    if !tracked || new_address == 0 {
        return;
    }
    let _ = LIFETIME.try_with(|lifetime| {
        let Some(mut state) = lifetime.get() else {
            return;
        };
        if state.address == old_address && !state.retired {
            state.address = new_address;
            lifetime.set(Some(state));
        }
    });
}

struct ProbeState {
    payloads: Vec<ObservedPayload>,
    #[cfg(target_os = "linux")]
    memory: File,
}

/// The system allocator, counting every allocation and reallocation on the calling thread.
#[derive(Debug)]
pub struct Counting {
    _private: (),
}

impl Counting {
    /// The counter, for a `#[global_allocator]` static.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for Counting {
    fn default() -> Self {
        Self::new()
    }
}

/// The destruction of one explicitly registered initialized payload prefix.
#[derive(Debug)]
pub struct ObservedPayload {
    address: usize,
    /// The initialized prefix length, excluding spare capacity.
    pub len: usize,
    /// Whether deallocation of the registered allocation was observed.
    pub freed: bool,
    /// Whether every registered byte was zero at deallocation.
    pub wiped: bool,
    /// Whether this allocation was freed by a successful reallocation.
    pub reallocated: bool,
    /// Bytes successfully copied by the OS reader, excluding spare capacity.
    pub bytes_read: usize,
    /// Whether the complete registered prefix was copied without an error.
    pub complete_read: bool,
    /// A failed read, invalid range, or unsupported platform prevents memory proof.
    pub read_error: Option<std::io::ErrorKind>,
}

/// The complete observation scope, including allocator reentry during an OS read.
#[derive(Debug)]
pub struct PayloadObservations {
    /// Every explicitly registered allocation, including those not freed in the scope.
    pub payloads: Vec<ObservedPayload>,
    /// Whether the OS reader reentered the allocator. A true value invalidates memory proof.
    pub reentered: bool,
}

/// A thread-bound observation scope. Dropping it disarms observation, including on panic.
#[derive(Debug)]
pub struct InitializedPayloadProbe {
    _thread_bound: PhantomData<Rc<()>>,
}

impl InitializedPayloadProbe {
    /// Begin observing payloads registered on this thread.
    ///
    /// # Safety
    /// Every payload registered during this scope, including by test instrumentation, must remain
    /// exclusively owned until it is deallocated on this thread or the scope ends. The registered
    /// prefix must remain initialized while owned; deallocation is observed through an OS copy,
    /// without dereferencing the Rust allocation after its owner gives it up.
    /// Registration must identify the allocation's base, not an interior slice. Moving a registered
    /// allocation to another thread before ending this scope is forbidden.
    ///
    /// # Panics
    /// Panics if another observation scope is already active on this thread.
    ///
    /// # Errors
    /// On Linux, opening `/proc/self/mem` must succeed before observation is armed. Other platforms
    /// still record registrations and frees, but report `Unsupported` instead of memory proof.
    #[allow(unsafe_code)]
    pub unsafe fn start() -> std::io::Result<Self> {
        #[cfg(target_os = "linux")]
        let memory = File::open("/proc/self/mem")?;
        PAYLOADS.with(|payloads| {
            let mut payloads = payloads.borrow_mut();
            assert!(payloads.is_none(), "one payload probe per thread");
            *payloads = Some(ProbeState {
                payloads: Vec::new(),
                #[cfg(target_os = "linux")]
                memory,
            });
        });
        REENTERED.with(|reentered| reentered.set(false));
        Ok(Self {
            _thread_bound: PhantomData,
        })
    }

    /// End observation and return the registered payloads and their destruction results.
    #[must_use]
    pub fn finish(self) -> PayloadObservations {
        let state =
            PAYLOADS.with(|payloads| payloads.borrow_mut().take().expect("active payload probe"));
        PayloadObservations {
            payloads: state.payloads,
            reentered: REENTERED.with(Cell::get),
        }
    }
}

impl Drop for InitializedPayloadProbe {
    fn drop(&mut self) {
        let _ = PAYLOADS.try_with(|payloads| {
            payloads.borrow_mut().take();
        });
    }
}

/// Register the initialized prefix of an owned allocation. Does nothing outside a probe scope.
/// Repeated registration of the same live allocation extends its known initialized prefix.
///
/// # Safety
/// `bytes` must start at the base of a live allocation. Its bytes must remain initialized and
/// exclusively owned until that allocation is freed on this thread or the active probe ends.
#[allow(unsafe_code)]
pub unsafe fn watch_initialized_payload(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    PAYLOADS.with(|payloads| {
        let mut payloads = payloads.borrow_mut();
        let Some(state) = payloads.as_mut() else {
            return;
        };
        let payloads = &mut state.payloads;
        let address = bytes.as_ptr() as usize;
        if let Some(payload) = payloads
            .iter_mut()
            .find(|payload| !payload.freed && payload.address == address)
        {
            payload.len = payload.len.max(bytes.len());
        } else {
            payloads.push(ObservedPayload {
                address,
                len: bytes.len(),
                freed: false,
                wiped: false,
                reallocated: false,
                bytes_read: 0,
                complete_read: false,
                read_error: None,
            });
        }
    });
}

fn registered(address: usize) -> bool {
    PAYLOADS
        .try_with(|payloads| {
            payloads.try_borrow().is_ok_and(|payloads| {
                payloads.as_ref().is_some_and(|payloads| {
                    payloads
                        .payloads
                        .iter()
                        .any(|payload| !payload.freed && payload.address == address)
                })
            })
        })
        .unwrap_or(false)
}

fn note_reentry() -> bool {
    let reading = READING.try_with(Cell::get).unwrap_or(false);
    if reading {
        let _ = REENTERED.try_with(|reentered| reentered.set(true));
    }
    reading
}

fn observe_deallocation(address: usize, layout: Layout, reallocated: bool) {
    let _ = PAYLOADS.try_with(|payloads| {
        let Ok(mut payloads) = payloads.try_borrow_mut() else {
            return;
        };
        let Some(state) = payloads.as_mut() else {
            return;
        };
        if let Some(payload) = state
            .payloads
            .iter_mut()
            .find(|payload| !payload.freed && payload.address == address)
        {
            payload.freed = true;
            payload.reallocated = reallocated;
            if payload.len > layout.size() || address.checked_add(payload.len).is_none() {
                payload.read_error = Some(std::io::ErrorKind::InvalidInput);
                return;
            }
            #[cfg(target_os = "linux")]
            {
                READING.with(|reading| reading.set(true));
                read_payload(&state.memory, payload);
                READING.with(|reading| reading.set(false));
            }
            #[cfg(not(target_os = "linux"))]
            {
                payload.read_error = Some(std::io::ErrorKind::Unsupported);
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn read_payload(memory: &File, payload: &mut ObservedPayload) {
    let mut chunk = [0u8; 4096];
    let mut all_zero = true;
    while payload.bytes_read < payload.len {
        let count = chunk.len().min(payload.len - payload.bytes_read);
        let offset = (payload.address as u64).checked_add(payload.bytes_read as u64);
        let Some(offset) = offset else {
            payload.read_error = Some(std::io::ErrorKind::InvalidInput);
            return;
        };

        match memory.read_at(&mut chunk[..count], offset) {
            Ok(0) => {
                payload.read_error = Some(std::io::ErrorKind::UnexpectedEof);
                return;
            }
            Ok(read) => {
                all_zero &= chunk[..read].iter().all(|byte| *byte == 0);
                payload.bytes_read += read;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                payload.read_error = Some(error.kind());
                return;
            }
        }
    }
    payload.complete_read = true;
    payload.wiped = all_zero;
}

fn bump() {
    let _ = ALLOCS.try_with(|c| c.set(c.get().saturating_add(1)));
}

// SAFETY: allocation operations forward their original arguments to System. Registered reallocations
// use GlobalAlloc's allocate/copy/free semantics so the actual old buffer reaches the observer. Only
// explicitly registered prefixes are copied by the OS, before System releases their allocations.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_reentry();
        bump();
        // SAFETY: forwarded verbatim under the caller's allocator contract.
        let allocated = unsafe { System.alloc(layout) };
        lifetime_allocated(allocated as usize, layout.size());
        allocated
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_reentry();
        bump();
        // SAFETY: forwarded verbatim under the caller's allocator contract.
        let allocated = unsafe { System.alloc_zeroed(layout) };
        lifetime_allocated(allocated as usize, layout.size());
        allocated
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        lifetime_deallocated(ptr as usize);
        if !note_reentry() {
            observe_deallocation(ptr as usize, layout, false);
        }
        // SAFETY: forwarded verbatim under the caller's allocator contract.
        unsafe {
            System.dealloc(ptr, layout);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        bump();
        note_reentry();
        let tracked = lifetime_reallocating(ptr as usize, layout.size(), new_size);
        if registered(ptr as usize) {
            // SAFETY: the realloc contract guarantees a valid nonzero new layout.
            let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
            // SAFETY: the new layout is valid and nonzero.
            let new = unsafe { System.alloc(new_layout) };
            if !new.is_null() {
                // SAFETY: the live blocks are distinct, contain at least the copied size, and the
                // old allocation is observed and freed exactly once. Raw copying allows spare bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                    observe_deallocation(ptr as usize, layout, true);
                    System.dealloc(ptr, layout);
                }
            }
            lifetime_reallocated(ptr as usize, new as usize, tracked);
            return new;
        }
        // SAFETY: forwarded verbatim under the caller's allocator contract.
        let reallocated = unsafe { System.realloc(ptr, layout, new_size) };
        lifetime_reallocated(ptr as usize, reallocated as usize, tracked);
        reallocated
    }
}

/// Allocations counted on THIS thread since it started or last [`reset`].
#[must_use]
pub fn allocations() -> u64 {
    ALLOCS.with(Cell::get)
}

/// Zero this thread's counter, returning what it held.
pub fn reset() -> u64 {
    ALLOCS.with(|c| c.replace(0))
}

/// How many allocations `f` made on this thread.
pub fn allocations_of(f: impl FnOnce()) -> u64 {
    allocations_with(f).0
}

/// How many allocations `f` made on this thread, and what it returned.
pub fn allocations_with<R>(f: impl FnOnce() -> R) -> (u64, R) {
    let before = allocations();
    let r = f();
    (allocations() - before, r)
}

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "tests/alloc_counter_tests.rs"]
mod tests;
