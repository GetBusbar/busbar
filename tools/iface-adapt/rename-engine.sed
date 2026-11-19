# The engine side of the interface rename: every path through the old single contract crate
# `busbar_plugin_abi` becomes a path through the crate that owns the item after the split
# (DESIGN-interface-revision C.2). Longest prefixes first. Portable: `sed -E -f` (GNU or BSD).
#
# 1. The engine's half of the call: the reference host.
s/busbar_plugin_abi::host_side::/busbar_plugin_host::/g
s/busbar_plugin_abi::host_side([^a-z_0-9:])/busbar_plugin_host\1/g
# 2. The seven kinds, by either spelling of the old path.
s/busbar_plugin_abi::kinds::(store|secret|auth|hook|export|plane|transport)::(store|secret|auth|hook|export|plane|transport)::/busbar_kind_\1::/g
s/busbar_plugin_abi::kinds::(store|secret|auth|hook|export|plane|transport)::(store|secret|auth|hook|export|plane|transport)([^a-z_0-9:])/busbar_kind_\1\3/g
s/busbar_plugin_abi::kinds::(store|secret|auth|hook|export|plane|transport)::/busbar_kind_\1::/g
s/busbar_plugin_abi::kinds::(store|secret|auth|hook|export|plane|transport)([^a-z_0-9:])/busbar_kind_\1\2/g
s/busbar_plugin_abi::(store|secret|auth|hook|export|plane|transport)::/busbar_kind_\1::/g
s/busbar_plugin_abi::(store|secret|auth|hook|export|plane|transport)([^a-z_0-9:])/busbar_kind_\1\2/g
s/busbar_plugin_abi::Store([^A-Za-z_0-9])/busbar_kind_store::Store\1/g
s/busbar_plugin_abi::Secret([^A-Za-z_0-9])/busbar_kind_secret::Secret\1/g
s/busbar_plugin_abi::Auth([^A-Za-z_0-9])/busbar_kind_auth::Auth\1/g
s/busbar_plugin_abi::Hook([^A-Za-z_0-9])/busbar_kind_hook::Hook\1/g
s/busbar_plugin_abi::Export([^A-Za-z_0-9])/busbar_kind_export::Export\1/g
s/busbar_plugin_abi::Plane([^A-Za-z_0-9])/busbar_kind_plane::Plane\1/g
s/busbar_plugin_abi::Transport([^A-Za-z_0-9])/busbar_kind_transport::Transport\1/g
# 3. Single-kind modules that leave the shared crate.
s/busbar_plugin_abi::fallback_usage/busbar_kind_plane::fallback_usage/g
s/busbar_plugin_abi::resource_admission/busbar_kind_plane::resource_admission/g
s/busbar_plugin_abi::memio/busbar_kind_transport_hyper::memio/g
# 4. The grouped imports (the shapes the engine has).
s/use busbar_plugin_abi::\{auth, export, hook, plane, secret, store, transport\};/use {busbar_kind_auth as auth, busbar_kind_export as export, busbar_kind_hook as hook, busbar_kind_plane as plane, busbar_kind_secret as secret, busbar_kind_store as store, busbar_kind_transport as transport};/
s/use busbar_plugin_abi::\{plane, transport\};/use {busbar_kind_plane as plane, busbar_kind_transport as transport};/
s/use busbar_plugin_abi::\{fail::CallError, host_side::caller::BoxFut\};/use {busbar_plugin_core::fail::CallError, busbar_plugin_host::caller::BoxFut};/
# 5. Everything else is the core contract: records, fail, types, plugin, need, host, stamp, versions,
#    slots, kind, secure, bridge, fp.
s/busbar_plugin_abi::/busbar_plugin_core::/g
s/busbar_plugin_abi([^a-z_0-9])/busbar_plugin_core\1/g
s/busbar_plugin_abi$/busbar_plugin_core/
# 6. One test is named after the old crate.
s/the_hash_is_busbar_plugin_abi_fp_parts/the_hash_is_busbar_plugin_core_fp_parts/
