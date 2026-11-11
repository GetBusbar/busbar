"""Supply the existing signed oracle from the runner's administrator-owned tool cache.

The protected policy pins the judge. Candidate builds receive no release credentials;
the existing oracle shim rechecks the installed binary's digest per use.
"""
from __future__ import annotations

import base64
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import urllib.parse
import urllib.request
import uuid

from check import Violation


TOOLS = Path('/srv/busbar-native-tools/oracle')
IMAGE_TOOLS = Path('/opt/busbar-native/oracle')


class OracleInputs(dict):
    """The signed oracle environment, supplied only after controller verification."""


class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        old, new = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(url)
        if (new.scheme, new.netloc) != (old.scheme, old.netloc):
            raise Violation('oracle download redirected outside its credential origin')
        return super().redirect_request(request, response, code, message, headers, url)


def load_pin(path, expected):
    payload = Path(path).read_bytes()
    if hashlib.sha256(payload).hexdigest() != expected:
        raise Violation('protected oracle pin digest differs')
    pin = json.loads(payload)
    if pin.get('schema') != 'busbar.native-oracle-pin/1' or pin.get('bin') != 'busbar-oracle':
        raise Violation('unsupported oracle pin')
    return pin


def stage(pin, arch, output, api=None):
    """Collect existing signed release bytes; never build or sign a replacement."""
    row = pin['platforms'][arch]
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    url = urllib.parse.urlsplit(row['canonical_asset'])
    expected = '/GetBusbar/busbar-release/-/releases/dev-bin/downloads/' + row['filename']
    if url.scheme != 'https' or url.netloc != 'github.com' or url.path != expected or url.query or url.fragment:
        raise Violation('oracle asset is not the protected canonical release')
    headers = {}
    address = row['canonical_asset']
    if api is not None:
        if api.server != 'https://' + url.netloc:
            raise Violation('oracle credential origin differs')
        # Imported private release links redirect the download route to a web
        # upload route, which accepts a session cookie rather than an API token.
        # Resolve only this signed filename and use GitLab's upload API directly.
        project_path = 'projects/GetBusbar%2Fbusbar-release'
        project = api.request(project_path)
        release = api.request(project_path + '/releases/dev-bin')
        links = [item for item in release['assets']['links']
                 if item.get('name') == row['filename']
                 and item.get('direct_asset_url') == row['canonical_asset']]
        if len(links) != 1:
            raise Violation('canonical signed oracle release link is absent or ambiguous')
        asset = urllib.parse.urlsplit(links[0]['url'])
        match = re.fullmatch(r'/-/project/([0-9]+)/uploads/([0-9a-f]{16,64})/([^/]+)', asset.path)
        if ((asset.scheme, asset.netloc) != (url.scheme, url.netloc) or asset.query or asset.fragment
                or match is None or int(match[1]) != project['id'] or match[3] != row['filename']):
            raise Violation('canonical oracle upload identity differs')
        address = api.server + '/api/v4/projects/' + match[1] + '/uploads/' + match[2] + '/' + urllib.parse.quote(row['filename'], safe='')
        headers['PRIVATE-TOKEN'] = api.token
    path = output / row['filename']
    try:
        opener = urllib.request.build_opener(SameOriginRedirect())
        with opener.open(urllib.request.Request(address, headers=headers), timeout=60) as incoming, path.open('xb') as outgoing:
            remaining = 128 * 1024**2
            while chunk := incoming.read(min(1024**2, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise Violation('oracle release asset exceeds byte limit')
                outgoing.write(chunk)
        actual = verify(path, pin, arch, output / 'signature-check')
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    path.chmod(0o555)
    record = {'schema': 'busbar.native-oracle-staging/1', 'source': pin['source'],
              'platform': arch, 'sha256': actual, 'canonical_asset': row['canonical_asset'],
              'signature_verified': True, 'artifact': str(path)}
    (output / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def install(pin, arch, artifact, work):
    """Administrator provisioning, explicitly separate from candidate qualification."""
    if os.geteuid() != 0:
        raise Violation('oracle cache installation requires the administrator identity')
    work = Path(work)
    work.mkdir(parents=True, exist_ok=False)
    actual = verify(Path(artifact), pin, arch, work / 'signature-check')
    directory = TOOLS / actual
    for parent in reversed((directory, *directory.parents)):
        if not parent.exists():
            parent.mkdir(mode=0o755)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Violation('oracle cache directory is not administrator owned')
    destination = directory / pin['bin']
    if not destination.exists():
        temporary = directory / ('.install-' + uuid.uuid4().hex)
        try:
            with Path(artifact).open('rb') as source, temporary.open('xb') as output:
                shutil.copyfileobj(source, output)
            temporary.chmod(0o555)
            # Reverify the actual copied bytes before publishing the cache entry.
            verify(temporary, pin, arch, work / 'installed-signature-check')
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    root_owned(destination)
    verify(destination, pin, arch, work / 'readback-signature-check')
    record = {'schema': 'busbar.native-oracle-installation/1', 'path': str(destination),
              'sha256': actual, 'source': pin['source'], 'signature_verified': True}
    (work / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


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
    execution = getattr(q, 'execution', None)
    judge = TOOLS / row['sha256'] / pin['bin']
    if execution is None:
        root_owned(judge)
    else:
        # Extract fixed signed bytes from the already present immutable image.
        # The container is never started and the candidate never sees its socket.
        directory = execution.control / 'oracle'
        directory.mkdir(mode=0o755)
        judge = directory / pin['bin']
        name = 'busbar-oracle-input-' + uuid.uuid4().hex
        try:
            created = execution._client(['create', '--pull=never', '--name', name,
                '--entrypoint', '/bin/false', execution.config['image']], capture_output=True)
            if created.returncode:
                raise Violation('pinned image oracle extraction could not create a container')
            copied = execution._client(['cp', name + ':' + str(IMAGE_TOOLS / row['sha256'] / pin['bin']), str(judge)], capture_output=True)
            if copied.returncode:
                raise Violation('signed oracle is absent from the pinned native image')
        finally:
            removed = execution._client(['rm', '--force', name], capture_output=True)
            absent = execution._client(['container', 'ls', '--all', '--quiet', '--filter', 'name=^/' + name + '$'], capture_output=True)
            if absent.returncode or absent.stdout.strip():
                raise Violation('oracle extraction container disposal was not confirmed')
        if judge.is_symlink() or not judge.is_file():
            raise Violation('image oracle is not a regular file')
        judge.chmod(0o555)
        execution.extra_readonly.append(directory)
    actual = verify(judge, pin, arch, q.evidence / 'oracle-identity')
    values = OracleInputs(BUSBAR_ORACLE_RELEASE_REPO=pin['repository'],
                 BUSBAR_ORACLE_RELEASE_REF=pin['source'],
                 BUSBAR_ORACLE_SHA256_LINUX_X86_64=pin['platforms']['x86_64']['sha256'],
                 BUSBAR_ORACLE_SHA256_LINUX_AARCH64=pin['platforms']['aarch64']['sha256'],
                 BUSBAR_ORACLE_CRATE=pin['crate'], BUSBAR_ORACLE_BIN=pin['bin'],
                 BUSBAR_ORACLE_JUDGE_PATH=str(judge))
    q.env.update(values)
    if execution is not None:
        execution.allow_oracle_inputs(values)
    q.receipt['oracle_judge'] = dict(source=pin['source'], sha256=actual,
                                   canonical_asset=row['canonical_asset'], signature_verified=True)
    q.save()
    q.run('oracle-judge-available', [str(judge), '--help'], timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('stage', 'install'))
    parser.add_argument('--pin', required=True, type=Path)
    parser.add_argument('--pin-sha256', required=True)
    parser.add_argument('--arch', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--artifact', type=Path)
    parser.add_argument('--credential-helper', action='store_true')
    args = parser.parse_args()
    pin = load_pin(args.pin, args.pin_sha256)
    if args.operation == 'stage':
        api = None
        if args.credential_helper:
            from admission import GitLab
            api = GitLab('https://github.com')
        result = stage(pin, args.arch, args.work, api)
    else:
        if args.artifact is None:
            parser.error('install requires --artifact')
        result = install(pin, args.arch, args.artifact, args.work)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
