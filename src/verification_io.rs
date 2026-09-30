//! Verification scans use a separate descriptor from serving. NOREUSE tells
//! Linux 6.3+ not to promote scanned pages; it does not evict hot boot/cache data.
use std::{fs::File, os::fd::AsRawFd};

pub(crate) fn sequential(file: &File) {
    // Advisory only: unsupported filesystems/kernels retain existing behavior.
    // Hashing still reads and verifies every byte. Never use global drop_caches
    // or DONTNEED here, since clients may concurrently serve the same files.
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_NOREUSE);
    }
}
