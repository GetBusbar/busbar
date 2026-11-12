"""Trusted prebuilt plugin dependency units: produced once, restored read-only.

Producer: core's protected dev push pipeline, after core qualification, or an
owner API pipeline on the protected PINNED_REF branch (a commit already on dev),
which runs only the producer and keys its files to that exact core commit. For each
product pinned in core's scripts/ci-product-pins.json it snapshots the product's
manifest graph and Cargo.lock at the pinned commit, replaces every Rust source
with an inert stub, and runs the exact plugin step commands in the ordinary
candidate confinement. No candidate code exists in that tree: only manifests
(data), the pinned lock and the locked third-party/host/SDK sources fetched by the
trusted collector. Every path (workspace) unit is stripped; the remaining
dependency units are published to core's generic package registry under a
content identity of everything that decides Cargo unit identity.

Consumer: plugin native qualification computes the same identity from its own
candidate lock and job environment. Absence, an identity mismatch, missing
provenance or any digest mismatch builds from scratch exactly as before. A hit is
extracted into a controller-only directory that no candidate invocation mounts;
each Cargo target gets a fresh writable copy, so a candidate can never write the
trusted units. Cargo's own fingerprints still rebuild every unit whose features,
profile, flags or sources differ (for example a candidate adding a feature to a
shared dependency), so a hit can only skip work, never a check.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = 'busbar.plugin-dependency-units/1'
PACKAGE = 'busbar-plugin-dependency-units'
PROJECT_API = 'https://github.com/api/v4/projects/3'
PRODUCER_JOB = 'plugin-dependency-units'
# The producer runs as GitLab `parallel: PRODUCER_SHARDS`; the server names each
# instance "plugin-dependency-units K/N". Every product belongs to exactly one
# shard by a stable digest of its repository name, so one product is only ever
# built by one shard index, and each shard index has its own resource_group:
# consecutive dev pushes never write one package file twice.
PRODUCER_SHARDS = 8
# Owner-run producer ref. Branch protection admits only owners; the controller
# requires its commit to be an ancestor-or-equal of current core dev. Its files
# carry that commit in their identity, so a consumer accepts them only while it
# qualifies against exactly that core host revision.
PINNED_REF = 'ci/dep-cache'
PRODUCER_JOB_NAME = re.compile(re.escape(PRODUCER_JOB) + r' ([1-9][0-9]*)/' + str(PRODUCER_SHARDS))
# Cargo fingerprints the absolute source path of every registry and Git unit.
# Every confined invocation gets its private Cargo home at this one path, in the
# producer and in every consumer job, so dependency fingerprints are portable.
CARGO_HOME_PATH = '/__busbar_cargo_home'
STUB = b'#![allow(dead_code)]\nfn main() {}\n'
MANIFEST = 'manifest.json'
MAX_MANIFEST_BYTES = 64 * 1024**2
MAX_ARCHIVE_BYTES = 6 * 1024**3
# Controller environment that reaches rustc or Cargo's unit identity. Absent
# keys are recorded as null so a later added flag changes the identity.
COMPILE_ENV = ('RUSTUP_TOOLCHAIN', 'RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
               'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'CARGO_BUILD_TARGET',
               'CARGO_INCREMENTAL', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS')


class Unavailable(Exception):
    """A reason to build from scratch. Never a qualification failure."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def plugin_commands(wrapper):
    """The dependency-compiling plugin steps of native_plugins.qualify_plugin.

    plugin-runtime is the build half of `cargo nextest run`, which invokes
    `cargo test --no-run` with the same selection. Doctests compile nothing a
    stub could add, but their dependency closure is built as for the tests.
    """
    return [
        ('clippy', ['cargo', 'clippy', '--locked', '--workspace', '--all-targets', '--all-features',
                    '--', '-D', 'warnings']),
        ('native-library', ['cargo', 'build', '--locked', '-p', wrapper, '--all-features', '--lib']),
        ('plugin-runtime', ['cargo', 'test', '--locked', '--workspace', '--all-features', '--no-run']),
        ('plugin-doctests', ['cargo', 'test', '--locked', '--workspace', '--all-features', '--doc',
                             '--no-fail-fast']),
    ]


def identity(repository, lock_sha256, image, env, target='x86_64-unknown-linux-gnu', wrapper=None,
             pinned_commit=None):
    """Everything outside the manifests that decides a dependency unit's bytes.

    A pinned-ref producer adds its exact core commit, so its files never share a
    key with the dev push producer's and match only consumers on that host.
    """
    value = {
        'schema': SCHEMA,
        'repository': repository,
        'lock_sha256': lock_sha256,
        'image': image,
        'target': target,
        'cargo_home': CARGO_HOME_PATH,
        'environment': {key: env.get(key) for key in COMPILE_ENV},
        'commands_sha256': sha256_bytes(canonical(plugin_commands(wrapper or '<wrapper>'))),
        'wrapper': wrapper,
    }
    if pinned_commit is not None:
        value['pinned_producer'] = {'ref': PINNED_REF, 'commit': pinned_commit}
    return value


def key(value):
    return sha256_bytes(canonical(value))


def stub_workspace(source, destination, *, revision=None):
    """Exact manifest graph and lock; every Rust file becomes an inert stub,
    except `[patch]` path crates that registry dependencies compile against
    (their own units are still stripped before upload).

    The manifest snapshot keeps every path so Cargo discovers the same targets.
    Only target roots are compiled; each one is `fn main() {}`, valid as a
    library, binary, build script, harness test or example.
    """
    from native_seed import manifest_snapshot
    kept = manifest_snapshot(source, destination, revision=revision, keep_patched=True)
    for path in destination.rglob('*.rs'):
        relative = path.relative_to(destination)
        if not any(relative.parts[:len(prefix.parts)] == prefix.parts for prefix in kept):
            path.write_bytes(STUB)
    return destination


def manifest_graph_sha256(root):
    """Paths plus manifest/lock bytes: the producer input, recorded for audit."""
    rows = []
    for path in sorted(p for p in root.rglob('*') if p.is_file()):
        relative = str(path.relative_to(root))
        data = path.read_bytes() if path.name in ('Cargo.toml', 'Cargo.lock') else b''
        rows.append([relative, sha256_bytes(data)])
    return sha256_bytes(canonical(rows))


def unit_matches(entry, names):
    """`<name>-<16 hex>[.ext]`, optionally `lib`-prefixed: plain and stripped stems count."""
    stem = entry.split('.', 1)[0]
    base, _, digest = stem.rpartition('-')
    if not (base and len(digest) == 16 and all(c in '0123456789abcdef' for c in digest)):
        base = stem
    return base in names or (base.startswith('lib') and base[3:] in names)


def strip_path_units(target, path_packages):
    """Remove every unit, output and cache that belongs to a path package.

    Only registry and Git units remain. Profile-root outputs, examples and
    incremental state are always removed; a case's own crates always compile.
    """
    names = set()
    for package in path_packages:
        names.update({package, package.replace('-', '_')})
    for name in ('.rustc_info.json', 'CACHEDIR.TAG', '.cargo-lock'):
        (target / name).unlink(missing_ok=True)
    for profile in [p for p in target.iterdir() if p.is_dir() and not p.is_symlink()]:
        for entry in list(profile.iterdir()):
            if entry.name in ('.fingerprint', 'deps', 'build'):
                for unit in list(entry.iterdir()):
                    if unit_matches(unit.name, names):
                        shutil.rmtree(unit) if unit.is_dir() and not unit.is_symlink() else unit.unlink()
            elif entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
    return target


def inventory(root):
    """Regular files and directories only; sha256 of every file."""
    files = {}
    for directory, names, entries in os.walk(root):
        for name in names + entries:
            path = Path(directory) / name
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode) and name in names:
                continue
            if not stat.S_ISREG(mode) or os.lstat(path).st_nlink != 1:
                raise Unavailable(f'dependency units contain a non-regular entry: {path.relative_to(root)}')
            files[str(path.relative_to(root))] = sha256_file(path)
    return files


def pack(root, archive):
    """Deterministic gzip tar: sorted, fixed owner and time."""
    files = inventory(root)
    with archive.open('xb') as raw:
        import gzip
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=3, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
                directories = sorted({str(parent) for name in files for parent in Path(name).parents
                                      if str(parent) != '.'})
                for name in directories:
                    info = tarfile.TarInfo(name)
                    info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
                    tar.addfile(info)
                for name in sorted(files):
                    path = root / name
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.mtime = path.stat().st_size, 0o644, 0
                    with path.open('rb') as stream:
                        tar.addfile(info, stream)
    return files


def unpack(archive, destination, expected):
    """Extract only regular files and directories at verified relative paths."""
    destination.mkdir(mode=0o700)
    seen = {}
    with tarfile.open(archive, mode='r:gz') as tar:
        for member in tar:
            relative = Path(member.name)
            if (relative.is_absolute() or not member.name or '..' in relative.parts
                    or member.name != relative.as_posix()):
                raise Unavailable('dependency archive path escapes its root')
            path = destination / relative
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.name not in expected or member.name in seen:
                raise Unavailable('dependency archive entry is unexpected: ' + member.name)
            path.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with tar.extractfile(member) as source, path.open('xb') as output:
                while chunk := source.read(1024**2):
                    digest.update(chunk)
                    output.write(chunk)
            seen[member.name] = digest.hexdigest()
    if seen != expected:
        raise Unavailable('dependency archive inventory differs from its manifest')
    return destination


def seal(root):
    """Read-only bits as well; the real boundary is that no candidate mounts it."""
    for directory, names, files in os.walk(root, topdown=False):
        for name in files:
            os.chmod(Path(directory) / name, 0o444)
        for name in names:
            os.chmod(Path(directory) / name, 0o555)
    os.chmod(root, 0o555)


def install(seed, destination, *, now=None):
    """A fresh writable target copy of the read-only seed.

    Every copied file gets one current timestamp. Restored units then postdate
    the job's freshly collected sources, and Cargo's rerun-if-changed and
    dependency-order mtime checks see a consistent tree. The sources are the
    exact locked registry/Git contents, so time carries no content identity.
    """
    if destination.exists() or destination.is_symlink():
        raise Unavailable('dependency target destination already exists')
    shutil.copytree(seed, destination, symlinks=True,
                    copy_function=shutil.copyfile)
    stamp = time.time() if now is None else now
    for directory, names, files in os.walk(destination):
        os.chmod(directory, 0o755)
        for name in files:
            path = Path(directory) / name
            # Cargo runs a restored build script again whenever its rerun-if
            # inputs differ; the sealed seed and the archive carry no mode bits.
            os.chmod(path, 0o755 if build_script(name) else 0o644)
            os.utime(path, (stamp, stamp), follow_symlinks=False)
    return destination


def build_script(name):
    """A compiled build script executable: build/<unit>/build-script-<name>[-<hash>]."""
    return name.startswith(('build-script-', 'build_script_')) and '.' not in name


def readonly_seed(path, execution):
    """The controller-owned seed must lie outside every candidate-writable root."""
    path = Path(path).resolve()
    if not path.is_dir() or path.is_symlink():
        raise Unavailable('dependency seed is not a directory')
    if execution is not None:
        for name in ('candidate', 'checkout', 'harness', 'trusted'):
            root = Path(execution.roots[name]).resolve()
            if path.is_relative_to(root) or root.is_relative_to(path):
                raise Unavailable('dependency seed is inside a candidate-mounted root: ' + name)
    return path


COMPILING = re.compile(r'^\s+(?:Compiling|Checking|Documenting) (?P<name>\S+) v(?P<version>\S+)(?P<rest>.*)$')


def rebuilt_dependency_units(text, members):
    """Count non-member units Cargo compiled, from its own human status lines."""
    rows = []
    for line in text.splitlines():
        match = COMPILING.match(line)
        if match and match['name'] not in members:
            rows.append(match['name'] + ' v' + match['version'])
    return rows


# --- GitLab generic package registry -------------------------------------------------

class SameOrigin(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        old, new = urllib.parse.urlsplit(request.full_url), urllib.parse.urlsplit(url)
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            raise Unavailable('package download changed origin')
        return super().redirect_request(request, response, code, message, headers, url)


class Registry:
    def __init__(self, token, api=PROJECT_API, opener=None, package=PACKAGE):
        self.api, self.token, self.package = api, token, package
        self.opener = opener or urllib.request.build_opener(SameOrigin())

    def _open(self, url, method='GET', data=None, timeout=120):
        request = urllib.request.Request(url, data=data, method=method, headers={'JOB-TOKEN': self.token})
        try:
            return self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise FileNotFoundError(url.split('?')[0]) from None
            raise Unavailable(f'package registry refused {method} (HTTP {error.code})') from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise Unavailable(f'package registry unavailable: {error}') from None

    def file_url(self, version, name):
        return f'{self.api}/packages/generic/{self.package}/{version}/{name}'

    def read(self, version, name, limit):
        with self._open(self.file_url(version, name)) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise Unavailable('package file exceeds its bound')
        return data

    def download(self, version, name, destination, size, digest):
        hasher = hashlib.sha256()
        with self._open(self.file_url(version, name), timeout=600) as response, destination.open('xb') as output:
            remaining = size
            while chunk := response.read(min(4 * 1024**2, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    raise Unavailable('dependency archive exceeds its manifest size')
                hasher.update(chunk)
                output.write(chunk)
        if remaining or hasher.hexdigest() != digest:
            raise Unavailable('dependency archive digest differs from its manifest')

    def json(self, path):
        with self._open(self.api + path) as response:
            return json.loads(response.read(MAX_MANIFEST_BYTES))

    def upload(self, version, name, path):
        with path.open('rb') as stream:
            data = stream.read() if path.stat().st_size < 64 * 1024**2 else stream
            request = urllib.request.Request(self.file_url(version, name) + '?select=package_file',
                                             data=data, method='PUT',
                                             headers={'JOB-TOKEN': self.token,
                                                      'Content-Length': str(path.stat().st_size)})
            try:
                with self.opener.open(request, timeout=1800) as response:
                    return json.loads(response.read(MAX_MANIFEST_BYTES))
            except urllib.error.HTTPError as error:
                raise Unavailable(f'package upload refused (HTTP {error.code})') from None

    def delete_package_file(self, package_id, file_id):
        """Delete one file of a cache package. The dependency-unit package is never pruned."""
        if self.package == PACKAGE:
            raise Unavailable('the dependency-unit package is never pruned')
        if type(package_id) is not int or type(file_id) is not int:
            raise Unavailable('package file identity is not an integer')
        with self._open(f'{self.api}/packages/{package_id}/package_files/{file_id}', method='DELETE'):
            pass


def provenance(registry, version, manifest):
    """Only files written once by one of core's two protected producer pipelines.

    A dev-key file must come from a protected dev push whose commit matches the
    manifest. A pinned-key file (identity carries pinned_producer, already equal
    to the consumer's host revision) must come from an API pipeline on exactly
    PINNED_REF at that commit, whose controller recorded a protected ref. A
    personal-token or other-pipeline upload, a duplicate file, or an API that
    will not answer is a miss: build from scratch.
    """
    package = getattr(registry, 'package', PACKAGE)
    query = urllib.parse.urlencode({'package_type': 'generic', 'package_name': package,
                                    'package_version': version})
    packages = [p for p in registry.json('/packages?' + query)
                if p.get('name') == package and p.get('version') == version]
    if len(packages) != 1:
        raise Unavailable('dependency package is absent or ambiguous')
    producer = manifest['producer']
    pinned = manifest['identity'].get('pinned_producer')
    if pinned is not None:
        if (pinned != {'ref': PINNED_REF, 'commit': producer['commit']} or producer.get('ref') != PINNED_REF
                or producer.get('source') != 'api' or producer.get('protected') is not True):
            raise Unavailable('pinned dependency producer is not the protected owner pipeline')
        ref, sources = PINNED_REF, (None, 'api')
    else:
        ref, sources = 'dev', (None, 'push')
    files = registry.json(f"/packages/{packages[0]['id']}/package_files?per_page=100")
    expected = {MANIFEST: None, manifest['archive']['name']: manifest['archive']['sha256']}
    for name, digest in expected.items():
        rows = [row for row in files if row.get('file_name') == name]
        if len(rows) != 1:
            raise Unavailable('dependency package file is absent or duplicated: ' + name)
        pipelines = rows[0].get('pipelines') or []
        if [p.get('id') for p in pipelines] != [producer['pipeline_id']]:
            raise Unavailable('dependency package file was not written by its producer pipeline')
        pipeline = pipelines[0]
        if pipeline.get('ref') != ref or pipeline.get('sha') != producer['commit'] \
                or pipeline.get('source') not in sources:
            raise Unavailable('dependency producer pipeline is not a protected '
                              + ('pinned API pipeline' if pinned is not None else 'dev push'))
        if digest is not None and rows[0].get('file_sha256') != digest:
            raise Unavailable('registry digest differs from the dependency manifest')
    return {'package_id': packages[0]['id'], 'pipeline_id': producer['pipeline_id'],
            'commit': producer['commit'], 'ref': ref}


# --- Consumer ------------------------------------------------------------------------

def consumer_identity(q, wrapper):
    lock = q.root / 'Cargo.lock'
    if not lock.is_file() or lock.is_symlink():
        raise Unavailable('candidate has no regular Cargo.lock')
    return identity(q.repository, sha256_file(lock), q.execution.config['image'], q.env, wrapper=wrapper)


def wrapper_package(policy, repository):
    rows = [p['name'] for p in policy.data['repositories'][repository].get('packages', [])
            if p['role'] in ('wrapper', 'combined')]
    if len(rows) != 1:
        raise Unavailable('dependency units need exactly one declared plugin export package')
    return rows[0]


def restore(q, registry=None):
    """Return a verified read-only seed directory, or None to build from scratch."""
    record = {'status': 'miss'}
    q.receipt['dependency_units'] = record
    entry = q.policy.data['repositories'].get(q.repository, {})
    if q.execution is None or entry.get('language') == 'c':
        record['status'] = 'not-applicable'
        return None
    seed = q.control / 'dependency-units'
    download = q.control / 'dependency-units.tar.gz'
    try:
        wanted = consumer_identity(q, wrapper_package(q.policy, q.repository))
        version = key(wanted)
        record['key'] = version
        registry = registry or Registry(os.environ['CI_JOB_TOKEN'])
        try:
            manifest = json.loads(registry.read(version, MANIFEST, MAX_MANIFEST_BYTES))
        except FileNotFoundError:
            # Only on a dev-key miss: the owner-run producer's files for exactly
            # the core host revision this job qualifies against.
            host = q.receipt.get('host_revision')
            if not (isinstance(host, str) and re.fullmatch('[0-9a-f]{40}', host)):
                return None
            wanted = dict(wanted, pinned_producer={'ref': PINNED_REF, 'commit': host})
            version = key(wanted)
            record['pinned_key'] = version
            try:
                manifest = json.loads(registry.read(version, MANIFEST, MAX_MANIFEST_BYTES))
            except FileNotFoundError:
                return None
        if manifest.get('schema') != SCHEMA or manifest.get('key') != version or manifest.get('identity') != wanted:
            raise Unavailable('dependency manifest identity differs')
        archive = manifest['archive']
        if not (isinstance(archive.get('bytes'), int) and 0 < archive['bytes'] <= MAX_ARCHIVE_BYTES
                and re.fullmatch('[0-9a-f]{64}', archive.get('sha256', ''))
                and archive.get('name') == 'units-' + archive['sha256'] + '.tar.gz'):
            raise Unavailable('dependency manifest archive is invalid')
        record['provenance'] = provenance(registry, version, manifest)
        started = time.monotonic()
        registry.download(version, archive['name'], download, archive['bytes'], archive['sha256'])
        unpack(download, seed, manifest['files'])
        seal(seed)
        record.update(status='hit', archive_sha256=archive['sha256'], archive_bytes=archive['bytes'],
                      files=len(manifest['files']), restore_seconds=round(time.monotonic() - started, 3),
                      product_commit=manifest['product']['commit'])
        return readonly_seed(seed, q.execution)
    except (Unavailable, KeyError, TypeError, ValueError, OSError, tarfile.TarError) as error:
        record.update(status='fallback', reason=str(error)[:500])
        for path in (seed,):
            if path.exists():
                for directory, names, _ in os.walk(path):
                    os.chmod(directory, 0o755)
                shutil.rmtree(path)
        return None
    finally:
        download.unlink(missing_ok=True)
        q.save()


def install_job_target(q, seed):
    """The job's shared CARGO_TARGET_DIR starts as a private copy of the seed."""
    if seed is None:
        return
    install(seed, Path(q.env['CARGO_TARGET_DIR']))
    q.receipt['dependency_units']['job_target'] = True
    q.save()


def discard(seed):
    if seed is not None and seed.exists():
        for directory, _, _ in os.walk(seed):
            os.chmod(directory, 0o755)
        shutil.rmtree(seed)


def account(q):
    """Record how many dependency units each step still compiled."""
    record = q.receipt.get('dependency_units')
    metadata = q.evidence / 'metadata.stdout'
    if not record or not metadata.is_file():
        return
    members = {p['name'] for p in json.loads(metadata.read_text())['packages'] if p.get('source') is None}
    members.add('architecture-shipping-probe')
    counts = {}
    for name in ('architecture', 'clippy', 'native-library', 'plugin-runtime', 'plugin-doctests'):
        path = q.evidence / (name + '.stderr')
        if path.is_file():
            counts[name] = len(rebuilt_dependency_units(path.read_text(errors='replace'), members))
    record['dependency_units_rebuilt'] = counts
    q.save()


# --- Producer ------------------------------------------------------------------------

def producer_shard(job_name):
    """0-based shard of a server-named producer job, or None for any other job."""
    match = PRODUCER_JOB_NAME.fullmatch(job_name or '')
    if match is None or not 1 <= int(match[1]) <= PRODUCER_SHARDS:
        return None
    return int(match[1]) - 1


def product_shard(repo):
    return int(hashlib.sha256(repo.encode()).hexdigest(), 16) % PRODUCER_SHARDS


def produce_product(q, product, policy, registry, *, image, upload=True, pinned=False):
    """Build one pinned product's dependency units from its stubbed manifest graph."""
    from check import resolve_shipping
    import check
    repository = 'GetBusbar/' + product['repo']
    wrapper = wrapper_package(policy, repository)
    if wrapper != product['package']:
        raise Unavailable('pinned product package differs from policy')
    wanted = identity(repository, product['lock_sha256'], image, q.env, wrapper=wrapper,
                      pinned_commit=os.environ['CI_COMMIT_SHA'] if pinned else None)
    version = key(wanted)
    row = {'repo': product['repo'], 'commit': product['commit'], 'key': version}
    try:
        registry.read(version, MANIFEST, MAX_MANIFEST_BYTES)
        row['status'] = 'present'
        return row
    except FileNotFoundError:
        pass
    canonical_source = q.work / 'canonical-inputs' / product['repo']
    base = q.work / 'dependency-units' / product['repo']
    stub = stub_workspace(canonical_source, base / 'stub', revision=product['commit'])
    if sha256_file(stub / 'Cargo.lock') != product['lock_sha256']:
        raise Unavailable('pinned product lock differs from its vector')
    graph_sha256 = manifest_graph_sha256(stub)
    metadata = json.loads(q.run('dependency-units-' + product['repo'] + '-metadata',
                                ['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=stub).read_text())
    target = base / 'target'
    previous = q.env['CARGO_TARGET_DIR']
    q.env['CARGO_TARGET_DIR'] = str(target)
    try:
        for name, argv in plugin_commands(wrapper):
            q.run('dependency-units-' + product['repo'] + '-' + name, argv, cwd=stub)
        # The architecture shipping probe, generated from the same manifests.
        scratch = q.harness / ('dependency-units-' + product['repo'])
        entries = [(name, e) for name, e in policy.packages.items() if e['repository'] == repository]
        saved, check.EXECUTION = check.EXECUTION, q.execution
        try:
            resolve_shipping(stub, entries, scratch)
        finally:
            check.EXECUTION = saved
        q.run('dependency-units-' + product['repo'] + '-architecture',
              ['cargo', 'build', '--manifest-path', str(scratch / 'shipping-probe/Cargo.toml'),
               '--target-dir', str(target)], cwd=stub)
    finally:
        q.env['CARGO_TARGET_DIR'] = previous
    members = {p['name'] for p in metadata['packages'] if p.get('source') is None}
    members.add('architecture-shipping-probe')
    owned = q.control / 'dependency-units-out' / product['repo']
    owned.parent.mkdir(exist_ok=True)
    from check import copy_candidate_tree
    copy_candidate_tree(target, owned)
    shutil.rmtree(base)
    strip_path_units(owned, members)
    archive_tmp = owned.parent / (product['repo'] + '.tar.gz')
    files = pack(owned, archive_tmp)
    digest = sha256_file(archive_tmp)
    archive = {'name': 'units-' + digest + '.tar.gz', 'sha256': digest, 'bytes': archive_tmp.stat().st_size}
    manifest = {'schema': SCHEMA, 'key': version, 'identity': wanted, 'archive': archive, 'files': files,
                'product': {'repo': product['repo'], 'commit': product['commit'],
                            'lock_sha256': product['lock_sha256'],
                            'manifest_graph_sha256': graph_sha256},
                'producer': {'pipeline_id': int(os.environ['CI_PIPELINE_ID']), 'job_id': int(os.environ['CI_JOB_ID']),
                             'commit': os.environ['CI_COMMIT_SHA'], 'ref': os.environ.get('CI_COMMIT_BRANCH'),
                             'source': os.environ.get('CI_PIPELINE_SOURCE'),
                             'protected': os.environ.get('CI_COMMIT_REF_PROTECTED') == 'true',
                             'dev_revision': q.receipt.get('target_revision')}}
    manifest_path = owned.parent / (product['repo'] + '.manifest.json')
    manifest_path.write_bytes(canonical(manifest))
    row.update(status='built', archive_bytes=archive['bytes'], files=len(files))
    if upload:
        # The archive first; the manifest is the commit marker consumers look for.
        registry.upload(version, archive['name'], archive_tmp)
        registry.upload(version, MANIFEST, manifest_path)
        row['status'] = 'published'
    shutil.rmtree(owned)
    archive_tmp.unlink()
    return row


def producer_kind(env=None):
    """'dev' (protected dev push), 'pinned' (owner API pipeline on protected PINNED_REF) or None.

    Both require the server's CI_COMMIT_REF_PROTECTED == 'true', as every other
    trusted cache producer does (native_release_stage.protected_tier).
    """
    from native_release_stage import protected_tier
    env = os.environ if env is None else env
    source, branch = env.get('CI_PIPELINE_SOURCE'), env.get('CI_COMMIT_BRANCH')
    if source == 'push' and protected_tier(env) == 'dev':
        return 'dev'
    if source == 'api' and branch == PINNED_REF and env.get('CI_COMMIT_REF_PROTECTED') == 'true':
        return 'pinned'
    return None


def produce(q, registry=None):
    """Publish missing dependency units for this shard's pinned products.

    The YAML rules admit only core's dev push pipelines and owner API pipelines
    on protected PINNED_REF. A pinned run also needs the constructor's proof that
    its commit is an ancestor-or-equal of current dev (receipt target_revision);
    consumers re-check the writing pipeline's ref, source and commit.
    """
    shard = producer_shard(os.environ.get('CI_JOB_NAME'))
    kind = producer_kind()
    if kind is not None and q.receipt.get('commit_ref_protected') is not True:
        kind = None
    if kind == 'pinned' and not isinstance(q.receipt.get('target_revision'), str):
        kind = None
    if not (q.repository == 'GetBusbar/busbar' and shard is not None and kind is not None
            and q.execution is not None):
        from check import Violation
        raise Violation('dependency units are produced only by the protected core dev push producer')
    # This receipt is producer evidence only; it never stands for qualification.
    q.receipt['schema'] = 'busbar.plugin-dependency-units-producer/1'
    registry = registry or Registry(os.environ['CI_JOB_TOKEN'])
    vector = json.loads((q.root / 'scripts/ci-product-pins.json').read_text())
    rows = []
    q.receipt['dependency_units_produced'] = rows
    q.receipt['dependency_units_shard'] = {'index': shard, 'total': PRODUCER_SHARDS}
    q.receipt['dependency_units_producer_kind'] = kind
    for product in vector['products']:
        repository = 'GetBusbar/' + product['repo']
        if product_shard(product['repo']) != shard:
            continue
        if repository not in q.policy.data['repositories'] or \
                q.policy.data['repositories'][repository].get('language') == 'c':
            continue
        try:
            rows.append(produce_product(q, product, q.policy, registry, image=q.execution.config['image'],
                                        pinned=kind == 'pinned'))
        except Exception as error:  # one product's failure must not block the others
            rows.append({'repo': product['repo'], 'status': 'failed', 'reason': str(error)[:500]})
        q.save()
    # The same shard's products also publish their core product-inputs test
    # image (native_product_images), built with the consumer's exact recipe.
    import native_product_images
    shard_products = [p for p in vector['products'] if product_shard(p['repo']) == shard]
    try:
        native_product_images.produce(q, shard_products,
                                      pinned_commit=os.environ['CI_COMMIT_SHA'] if kind == 'pinned' else None)
    except Exception as error:  # images are an optimisation; never block units
        q.receipt['product_images_produced'] = [{'status': 'failed', 'reason': str(error)[:500]}]
        q.save()
    failed = [row['repo'] for row in rows if row.get('status') == 'failed']
    if failed:
        # Every product is attempted first; a fill that published nothing must not pass.
        from check import Violation
        raise Violation('dependency units failed for ' + ', '.join(failed))
    return rows
