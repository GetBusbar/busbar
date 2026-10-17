#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Port of the two "make a migrated config accept-able" steps that
# `crates/busbar/tests/migration_corpus.rs` applies AFTER `--migrate-config` and BEFORE `--validate`:
#
#   1. apply_deferred_decisions() — the two decisions a migrator explicitly refuses to invent (a
#      signing key, an admin credential) get supplied here, mechanically, the same way the Rust test
#      does it: if `auth.chain` names `keys`, make sure `auth.signing_key` and `auth.admin_auth` exist
#      (only filling in what is MISSING — a config that already set them, e.g. via a real `file:`
#      secret, is left alone), and make sure `identity-providers.admin-tokens` exists so `admin_auth:
#      [admin-tokens]` resolves.
#   2. rewrite_file_secret_paths() — a genuine `{ file: <path> }` / block `file: <path>` secret ref
#      (the KEY is exactly `file`, not `providers_file`/`cert_file`/etc, and it is not inside a YAML
#      comment) names a PRODUCTION path that cannot exist here. Repoint it at a stand-in file this
#      script writes, so `--validate` is judging the migration, not this machine's filesystem layout.
#
# This is read by record.sh for the `config.migrate|<tag>|validate-migrated` oracle cells ONLY. It is
# a faithful, line-by-line port of the Rust rules — see crates/busbar/tests/migration_corpus.rs
# (apply_deferred_decisions, providers_for is mirrored separately as corpus_providers_for() in
# record.sh, rewrite_file_secret_paths) — not a reinterpretation of them.
#
# Usage:
#   apply-deferred-decisions.py <migrated.yaml> --stand-in <path-to-write-secret-file>
# Prints the ready-to-validate YAML on stdout. Writes 64 hex bytes to --stand-in ONLY if the document
# contains a genuine `file:` secret ref (so the caller never has to guess whether one exists).

import sys
import argparse

try:
    import yaml
except ImportError:
    sys.stderr.write("apply-deferred-decisions.py needs PyYAML (pip install pyyaml)\n")
    sys.exit(2)


def apply_deferred_decisions(text: str) -> str:
    """Mirrors `apply_deferred_decisions` in migration_corpus.rs, mapping-shape for mapping-shape."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return text
    if not isinstance(doc, dict):
        return text
    auth = doc.get("auth")
    if not isinstance(auth, dict):
        return text
    chain = auth.get("chain")
    names_keys = isinstance(chain, list) and any(v == "keys" for v in chain)
    if not names_keys:
        return text

    # A 64-hex ed25519 secret, the shape `--generate-signing-key` emits. Fixed and never touching
    # disk beyond the temp validate run, same rationale as the Rust test.
    if "signing_key" not in auth:
        auth["signing_key"] = {"env": "BUSBAR_TEST_SIGNING_KEY"}
    if "admin_auth" not in auth:
        auth["admin_auth"] = ["admin-tokens"]

    # `admin_auth` references it by bare name, so the provider has to be defined.
    idp = doc.get("identity-providers")
    if not isinstance(idp, dict):
        idp = {}
        doc["identity-providers"] = idp
    if "admin-tokens" not in idp:
        idp["admin-tokens"] = {
            "module": "admin-tokens",
            "token": {"env": "BUSBAR_TEST_ADMIN_TOKEN"},
        }

    try:
        return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
    except yaml.YAMLError:
        return text


def yaml_comment_start(line: str) -> int:
    """The byte offset a YAML line-comment begins at, or len(line) if there is none.

    Mirrors `yaml_comment_start`: a `#` only opens a comment at line start or preceded by whitespace.
    """
    for i, ch in enumerate(line):
        if ch == "#" and (i == 0 or line[i - 1].isspace()):
            return i
    return len(line)


def rewrite_file_secret_paths(text: str, stand_in: str) -> str:
    """Mirrors `rewrite_file_secret_paths`: repoint only a genuine `file:` secret KEY, never a
    `*_file:` key and never anything past a line's comment marker."""
    out_lines = []
    for line in text.split("\n"):
        code_end = yaml_comment_start(line)
        code, comment = line[:code_end], line[code_end:]
        rest = code
        pieces = []
        while True:
            rel = rest.find("file:")
            if rel == -1:
                pieces.append(rest)
                break
            head, tail = rest[:rel], rest[rel:]
            after_key = tail[len("file:"):]
            before = head.rstrip()
            if before == "" or before.endswith("{"):
                close = after_key.find("}")
                if close == -1:
                    close = len(after_key)
                pieces.append(head)
                pieces.append("file: ")
                pieces.append(stand_in)
                pieces.append(" ")
                pieces.append(after_key[close:])
                break
            pieces.append(head)
            pieces.append("file:")
            rest = after_key
        out_lines.append("".join(pieces) + comment)
    # split('\n') then join with '\n' round-trips exactly except we must not add a trailing line.
    return "\n".join(out_lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("migrated", help="path to the migrated YAML (output of --migrate-config)")
    ap.add_argument("--stand-in", required=True, help="path to write the file: secret stand-in to")
    args = ap.parse_args()

    with open(args.migrated, "r", encoding="utf-8") as f:
        text = f.read()

    ready = apply_deferred_decisions(text)

    if "file:" in ready:
        with open(args.stand_in, "w", encoding="utf-8") as f:
            f.write("a" * 64)
        ready = rewrite_file_secret_paths(ready, args.stand_in)

    sys.stdout.write(ready)
    return 0


if __name__ == "__main__":
    sys.exit(main())
