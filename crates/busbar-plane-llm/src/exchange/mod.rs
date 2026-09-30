//! THE PLANE'S EXCHANGE WITH THE KERNEL, sans I/O: what `arrive` reads off an arrival, what an
//! attempt sends to the far end and what the far end's answer becomes for the caller. Every
//! function here is pure over bytes the kernel hands in; the door adapts them to the plane ABI.

pub mod multipart;
