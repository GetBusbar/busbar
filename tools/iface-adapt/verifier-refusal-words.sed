# crates/busbar-artifact-verifier/src/refusal.rs: the words of a version or fingerprint refusal. The
# loader's `agree` writes `have` as "built for transport 2.4" and `want` as "this engine speaks
# transport 2.3: upgrade the engine or use the plugin's build for transport 2.3" (both numbers named),
# so the sentence is "'<name>' is <have>; <want>". Portable: `sed -E -f`.
s/^                "is built for \{have\}; this busbar \{\}\.\{\}\.\{\} requires \{want\} exactly",$/                "is {have}; {want}"/
/^                ENGINE\.major, ENGINE\.minor, ENGINE\.patch$/d
s/^                "is built for plugin mechanism \{have\}; this busbar requires \{want\} exactly"$/                "is {have}; {want}"/
s/^                "is built against a different ABI \(\{field\} \{have\}, expected \{want\}\) at the same version — a mismatched SDK build"$/                "was built from another contract than this engine's ({field}: {have}; expected {want}) — a mismatched SDK build"/
