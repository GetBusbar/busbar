# crates/busbar-artifact-verifier/src/scan.rs: read stamp format 3 (the fields of
# `busbar_plugin_abi::stamp::Stamp` on house/iface-solo). Portable: `sed -E -f`.
s/^pub const STAMP_FORMAT: u32 = 2;$/pub const STAMP_FORMAT: u32 = 3;/
s/"format is not 2"/"format is not 3"/
s/^        mechanism: u32_at\(32\),$/        core_abi: u32_at(32),/
s/^        mechanism_layout: u64_at\(48\),$/        core_layout: u64_at(48),/
s/^        semantic: u64_at\(56\),$/        kind_minor: u32_at(56),\
        core_minor: u32_at(60),/
s/^        mechanism_semantic: u64_at\(64\),$/        _reserved2: array(b, 64),/
/^    if let Some\(i\) = stamp\._reserved\.iter\(\)\.position\(\|&b\| b != 0\) \{$/i\
\    if let Some(i) = stamp._reserved2.iter().position(|\&b| b != 0) {\
\        return Err(malformed(64 + i as u32, "a reserved byte is not zero"));\
\    }
