// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Request frames: request-scoped memory that exists before the request does.
//!
//! A pool is built with its owner, off the request path. A request takes a frame, writes its
//! hand-off data into the frame's own buffers once, and shares the frame with any task that may
//! outlive it. Sharing is a reference count. The last holder to let go clears the frame and
//! returns it. Nothing here allocates while the pool has a free frame.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// What a frame's value does before its next use: clear every buffer, keeping its capacity, and
/// wipe every buffer that held a secret.
pub trait Reset {
    fn reset(&mut self);
}

/// The frames of one owner. Invariant: an `Arc<T>` of a pool is held only by the pool's free list
/// or by a [`Frame`]; it is never cloned anywhere else.
pub struct FramePool<T> {
    free: Mutex<Vec<Arc<T>>>,
}

/// One holder of one frame.
pub struct Frame<T: Reset> {
    slot: Option<Arc<T>>,
    home: Arc<FramePool<T>>,
}

impl<T: Reset + Default> FramePool<T> {
    /// Built with its owner, off the request path: `frames` values made now.
    #[must_use]
    pub fn build(frames: usize) -> Arc<Self> {
        let mut free = Vec::with_capacity(frames);
        free.resize_with(frames, || Arc::new(T::default()));
        Arc::new(Self {
            free: Mutex::new(free),
        })
    }

    /// A frame for one request. Pops a free frame; makes one only when demand has passed every
    /// earlier peak (the pool then keeps it).
    #[must_use]
    pub fn take(self: &Arc<Self>) -> Frame<T> {
        let free = self.lock().pop();
        Frame {
            slot: Some(free.unwrap_or_else(Self::grown)),
            home: Arc::clone(self),
        }
    }

    #[cold]
    #[inline(never)]
    fn grown() -> Arc<T> {
        Arc::new(T::default())
    }
}

impl<T> FramePool<T> {
    fn lock(&self) -> MutexGuard<'_, Vec<Arc<T>>> {
        self.free.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many frames rest in the pool now.
    #[must_use]
    pub fn resting(&self) -> usize {
        self.lock().len()
    }
}

impl<T: Reset> Frame<T> {
    /// The value, to write: `Some` while this is the only holder. That is always so before the
    /// first [`Frame::share`], and so again once every other holder has let go.
    pub fn fill(&mut self) -> Option<&mut T> {
        self.slot.as_mut().and_then(Arc::get_mut)
    }

    /// Another holder of the same frame: a reference count, no allocation, no copy.
    #[must_use]
    pub fn share(&self) -> Self {
        Frame {
            slot: self.slot.clone(),
            home: Arc::clone(&self.home),
        }
    }
}

impl<T: Reset> Clone for Frame<T> {
    fn clone(&self) -> Self {
        self.share()
    }
}

impl<T: Reset> std::ops::Deref for Frame<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.slot
            .as_deref()
            .expect("a frame holds its slot until it is dropped")
    }
}

impl<T: Reset> Drop for Frame<T> {
    fn drop(&mut self) {
        let Some(mut slot) = self.slot.take() else {
            return;
        };
        // Every release of this pool's frames passes this lock, so exactly one holder sees
        // itself as the last.
        let last = {
            let _serial = self.home.lock();
            if Arc::get_mut(&mut slot).is_some() {
                Some(slot)
            } else {
                drop(slot);
                None
            }
        };
        if let Some(mut slot) = last {
            // The last holder: nobody else can reach the value, so it is cleared outside the lock.
            if let Some(value) = Arc::get_mut(&mut slot) {
                value.reset();
            }
            self.home.lock().push(slot);
        }
    }
}
