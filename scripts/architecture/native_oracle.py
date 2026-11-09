"""Supply the existing signed oracle from the runner's administrator-owned tool cache.

The protected policy pins the judge. Candidate builds receive no release credentials;
the existing oracle shim rechecks the installed binary's digest per use.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import platform
import stat
import subprocess

from check import Violation


TOOLS = Path('/srv/busbar-native-tools/oracle')


def root_owned(path):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Violation('oracle cache must be root-owned and not writable by builds')
    if not path.is_file() or not path.stat().st_mode & 0o111:
        raise Violation('oracle judge must be an executable regular file')


def verify(path, pin, arch, evidence):
    row = pin['platforms'][arch]
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != row['sha256']:
        raise Violation('installed oracle judge digest differs from protected pin')
    evidence.mkdir(parents=True, exist_ok=False)
    key, message, signature = (evidence / name for name in ('release-key.pem', 'message', 'signature'))
    key.write_text(pin['release_key_pem'])
    message.write_text(row['filename'] + '\n' + actual + '\n')
    signature.write_bytes(base64.b64decode(row['signature'], validate=True))
    result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(key),
                             '-rawin', '-in', str(message), '-sigfile', str(signature)],
                            capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise Violation('oracle judge signature does not match the protected release key')
    return actual


def prepare(q):
    pin = json.loads((q.trusted / 'ci/native-oracle.json').read_text())
    arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    if platform.system() != 'Linux' or arch not in pin['platforms']:
        raise Violation('no protected oracle judge for this native platform')
    row = pin['platforms'][arch]
    judge = TOOLS / row['sha256'] / pin['bin']
    root_owned(judge)
    actual = verify(judge, pin, arch, q.evidence / 'oracle-identity')
    q.env.update(BUSBAR_ORACLE_RELEASE_REPO=pin['repository'],
                 BUSBAR_ORACLE_RELEASE_REF=pin['source'],
                 BUSBAR_ORACLE_SHA256_LINUX_X86_64=pin['platforms']['x86_64']['sha256'],
                 BUSBAR_ORACLE_SHA256_LINUX_AARCH64=pin['platforms']['aarch64']['sha256'],
                 BUSBAR_ORACLE_CRATE=pin['crate'], BUSBAR_ORACLE_BIN=pin['bin'],
                 BUSBAR_ORACLE_JUDGE_PATH=str(judge))
    q.receipt['oracle_judge'] = dict(source=pin['source'], sha256=actual,
                                   canonical_asset=row['canonical_asset'], signature_verified=True)
    q.save()
    q.run('oracle-judge-available', [str(judge), '--help'], timeout=30)
