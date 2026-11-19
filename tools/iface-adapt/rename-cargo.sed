# A manifest that named the old single contract crate names the crates that replace it. Every engine
# crate gets the core, the host half and the seven kinds; the compile-and-fix card then drops the ones
# its crate does not use (the unused-dependency check names them). Portable: `sed -E -f` (GNU or BSD).
s#^busbar-plugin-abi = \{ path = "(\.\./|\.\./\.\./crates/)busbar-plugin-abi", features = \["host"\] \}$#busbar-plugin-core = { path = "\1busbar-plugin-core" }\
busbar-plugin-host = { path = "\1busbar-plugin-host" }\
busbar-kind-store = { path = "\1busbar-kind-store" }\
busbar-kind-secret = { path = "\1busbar-kind-secret" }\
busbar-kind-auth = { path = "\1busbar-kind-auth" }\
busbar-kind-hook = { path = "\1busbar-kind-hook" }\
busbar-kind-export = { path = "\1busbar-kind-export" }\
busbar-kind-plane = { path = "\1busbar-kind-plane" }\
busbar-kind-transport = { path = "\1busbar-kind-transport" }#
s#^busbar-plugin-abi = \{ path = "(\.\./|\.\./\.\./crates/)busbar-plugin-abi", default-features = false \}$#busbar-plugin-core = { path = "\1busbar-plugin-core" }#
s#^busbar-plugin-abi = \{ path = "(\.\./|\.\./\.\./crates/)busbar-plugin-abi" \}$#busbar-plugin-core = { path = "\1busbar-plugin-core" }#
