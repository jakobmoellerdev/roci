//! Bounded pools of reusable I/O buffers for the blob read and upload paths.
//!
//! Streaming allocates a large buffer per chunk on one thread (a blocking-pool
//! thread for reads, an async worker for upload batches) and frees it on
//! another. With per-thread allocator heaps that cross-thread churn is retained
//! rather than reused, ratcheting RSS up under load. Recycling a bounded set of
//! buffers keeps the working set flat regardless of which thread frees them.

use bytes::Bytes;
use std::sync::Mutex;

/// A fixed-size-class pool holding at most `max` idle buffers.
pub(crate) struct BufPool {
    capacity: usize,
    max: usize,
    idle: Mutex<Vec<Vec<u8>>>,
}

impl BufPool {
    pub(crate) const fn new(capacity: usize, max: usize) -> Self {
        Self {
            capacity,
            max,
            idle: Mutex::new(Vec::new()),
        }
    }

    /// An empty buffer with at least the pool's capacity.
    pub(crate) fn get(&'static self) -> Vec<u8> {
        let reused = self.idle.lock().expect("buffer pool poisoned").pop();
        reused.unwrap_or_else(|| Vec::with_capacity(self.capacity))
    }

    /// Return `buf` for reuse (dropped when the pool is full or it has shrunk
    /// below the size class).
    pub(crate) fn put(&'static self, mut buf: Vec<u8>) {
        if buf.capacity() < self.capacity {
            return;
        }
        buf.clear();
        let mut idle = self.idle.lock().expect("buffer pool poisoned");
        if idle.len() < self.max {
            idle.push(buf);
        }
    }

    /// Freeze `buf` into [`Bytes`] that return it to this pool when the last
    /// reference (e.g. hyper, after writing it) drops.
    pub(crate) fn freeze(&'static self, buf: Vec<u8>) -> Bytes {
        Bytes::from_owner(Pooled {
            buf: Some(buf),
            pool: self,
        })
    }
}

struct Pooled {
    buf: Option<Vec<u8>>,
    pool: &'static BufPool,
}

impl AsRef<[u8]> for Pooled {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_deref().unwrap_or_default()
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.put(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_buffers_return_to_the_pool_and_are_reused() {
        static POOL: BufPool = BufPool::new(64, 2);
        let mut a = POOL.get();
        a.extend_from_slice(b"hello");
        let ptr = a.as_ptr();
        let bytes = POOL.freeze(a);
        assert_eq!(&bytes[..], b"hello");
        let clone = bytes.clone();
        drop(bytes);
        assert!(POOL.idle.lock().unwrap().is_empty(), "still referenced");
        drop(clone);
        // The same allocation comes back, emptied.
        let b = POOL.get();
        assert_eq!((b.as_ptr(), b.len()), (ptr, 0));
    }

    #[test]
    fn pool_is_bounded_and_rejects_shrunken_buffers() {
        static POOL: BufPool = BufPool::new(64, 1);
        POOL.put(Vec::with_capacity(64));
        POOL.put(Vec::with_capacity(64));
        POOL.put(Vec::with_capacity(8));
        assert_eq!(POOL.idle.lock().unwrap().len(), 1);
    }
}
