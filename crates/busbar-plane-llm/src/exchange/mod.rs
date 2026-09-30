//! THE PLANE'S EXCHANGE WITH THE KERNEL, sans I/O: what `arrive` reads off an arrival, what an
//! attempt sends to the far end and what the far end's answer becomes for the caller. Every
//! function here is pure over bytes the kernel hands in; the door adapts them to the plane ABI.

pub mod arrive;
pub mod attempt;
pub mod multipart;
pub mod probe;
pub mod refuse;
pub mod shaping;
