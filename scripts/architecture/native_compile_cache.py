"""Trusted core compile target: one dev push's Cargo target dir, restored by later runs.

Every core native qualification compiles the same root and dist/default graphs
from an empty CARGO_TARGET_DIR. Between two commits almost every unit is
identical: all third-party units, and every workspace crate the change does not
reach (with its lib, test harness, bins and build-script output).

Producer: core native qualification of a protected dev push (and the owner's
API pipeline on the protected native_dep_cache.PINNED_REF). After the job's
last candidate step the controller snapshots the job's CARGO_TARGET_DIR plus a
content inventory of the exact source tree that produced it, and publishes
both to core's generic package registry under a key over everything outside the
sources that decides Cargo unit identity (toolchain, image, target, compile
environment, command recipe, checkout and Cargo home paths). Dev code is trusted
for dev, so its units are; nothing an MR or plugin pipeline produces is ever
written. A producer that restored a previous target records one more generation;
the chain is bounded (MAX_GENERATIONS), after which a consumer treats the entry
as a miss and its own dev run rebuilds from empty, so any defect carried in a
target cannot outlive a bounded number of dev pushes.

Consumer: the same key, protected dev provenance (writing pipeline, ref, source,
commit), archive and per-file digests, extraction into a controller-only
directory and a private writable copy as the job's CARGO_TARGET_DIR -- exactly
the plugin dependency-unit model (native_dep_cache). Anything absent or doubtful
starts from an empty target as before.

Cargo decides freshness of a workspace (path) unit by modification time: a
fresh checkout postdates every restored unit, so without help every workspace
crate rebuilds. stamp_checkout() therefore sets times by content: every file
whose sha256 equals the producer's file at the same path, and every directory
whose entry names equal the producer's, gets the producer's own modification
time (Cargo records a build script's newest package mtime and compares it for
equality, so only the exact time keeps it fresh); everything else (changed,
added, or a directory that gained an entry) gets a time after the restored
units. Cargo then rebuilds exactly the units whose tracked inputs changed, plus
their dependents -- the same rule it applies to any incremental build. A removed
file, or a change to any Cargo manifest, lockfile, Cargo configuration or
toolchain file, stamps the whole checkout new: every workspace unit rebuilds and
only third-party units (whose identity Cargo hashes) are reused.

What this never changes: the commands, features, profiles, lints and tests. A
reused test binary is still executed by every step that ran it; a reused clippy
unit replays its cached diagnostics under the same `-D warnings`.
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
import urllib.parse

import native_dep_cache as units
from native_dep_cache import Unavailable, canonical, key, sha256_bytes, sha256_file

SCHEMA = 'busbar.core-compile-target/1'
PACKAGE = 'busbar-core-compile-target'
TARGET = 'x86_64-unknown-linux-gnu'
INVENTORY = 'sources.json'
MAX_ARCHIVE_BYTES = 8 * 1024**3
# A producer that started from a restored target is generation parent + 1. A
# consumer refuses an entry at this generation, so at most this many dev pushes
# ever inherit units from a cold build before one rebuilds everything.
MAX_GENERATIONS = 16
# Cargo (or rustup) inputs that are not tracked per unit by modification time:
# any difference makes every workspace unit rebuild.
GLOBAL_INPUTS = re.compile(r'(^|/)(Cargo\.toml|Cargo\.lock|rust-toolchain(\.toml)?)$|(^|/)\.cargo/')
# Never part of the source inventory: VCS control and Cargo output directories.
EXCLUDED = ('.git', 'target', 'dist/default/target')
# The earliest restore time accepted: restored units must postdate every source.
OLD = 946684800  # 2000-01-01T00:00:00Z
ENVIRONMENT = (*units.COMPILE_ENV, 'CI', 'CARGO_PROFILE_RELEASE_DEBUG')


def excluded(relative):
    return any(relative == name or relative.startswith(name + '/') for name in EXCLUDED)


def source_inventory(root):
    """[sha256, mtime_ns] of every regular file; [entry-names digest, mtime_ns] of
    every directory. Symbolic links are recorded by their target text, so a
    retargeted link is a change. Anything else (device, socket) is unusable.
    """
    root = Path(root)
    files, directories = {}, {}
    for directory, names, entries in os.walk(root):
        relative_directory = Path(directory).relative_to(root).as_posix()
        relative_directory = '' if relative_directory == '.' else relative_directory
        names[:] = sorted(n for n in names if not excluded((relative_directory + '/' + n).lstrip('/')))
        listing = []
        for name in sorted(names + entries):
            relative = (relative_directory + '/' + name).lstrip('/')
            if excluded(relative):
                continue
            listing.append(name)
            path = Path(directory) / name
            info = os.lstat(path)
            if stat.S_ISDIR(info.st_mode):
                continue
            if stat.S_ISLNK(info.st_mode):
                files[relative] = ['link:' + os.readlink(path), info.st_mtime_ns]
            elif stat.S_ISREG(info.st_mode):
                files[relative] = [sha256_file(path), info.st_mtime_ns]
            else:
                raise Unavailable('source tree contains a special file: ' + relative)
        directories[relative_directory] = [sha256_bytes(canonical(listing)), os.lstat(directory).st_mtime_ns]
    return {'files': files, 'directories': directories}


def changed_paths(current, produced):
    def same(table, path, row):
        old = produced[table].get(path)
        return isinstance(old, list) and len(old) == 2 and old[0] == row[0] and isinstance(old[1], int)
    files = sorted(path for path, row in current['files'].items() if not same('files', path, row))
    removed = sorted(set(produced['files']) - set(current['files']))
    directories = sorted(path for path, row in current['directories'].items()
                         if not same('directories', path, row))
    return files, removed, directories


def stamp_checkout(root, produced, restored_at, *, current=None):
    """Set source times by content against the producer's inventory.

    restored_at is the time given to every restored target file; changed paths
    get a later time, unchanged paths the producer's. Returns the decision.
    """
    root = Path(root)
    current = current or source_inventory(root)
    files, removed, directories = changed_paths(current, produced)
    global_change = sorted(p for p in files + removed if GLOBAL_INPUTS.search(p)) or removed[:1]
    if restored_at <= OLD or restored_at > time.time() + 60:
        raise Unavailable('restore time is implausible')
    new = int((restored_at + 2) * 1e9)
    newest = max([row[1] for table in ('files', 'directories') for row in produced[table].values()] or [0])
    if newest >= int(restored_at * 1e9):
        raise Unavailable('producer sources postdate the restored units')
    changed = set(files) | set(directories)
    for table in ('directories', 'files'):
        for relative in current[table]:
            stamp = new if global_change or relative in changed else produced[table][relative][1]
            path = root / relative if relative else root
            os.utime(path, ns=(stamp, stamp), follow_symlinks=False)
    return {'changed_files': len(files), 'removed_files': len(removed),
            'changed_directories': len(directories), 'global_inputs_changed': global_change[:20],
            'all_workspace_units_rebuild': bool(global_change),
            'changed_sample': files[:20]}


def install(seed, destination, restored_at, executables=None):
    """Private writable copy of the read-only seed; every file at restored_at.

    Build-script and test executables keep their execute bit (Cargo runs a
    restored build script whenever its rerun-if inputs differ), named by the
    verified manifest when given, else taken from the seed itself.
    """
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise Unavailable('compile target destination already exists')
    shutil.copytree(seed, destination, symlinks=True, copy_function=shutil.copyfile)
    return settle(destination, restored_at, executables, seed)


def settle(destination, restored_at, executables=None, seed=None):
    """Writable modes, execute bits and one restore time on an extracted target."""
    for directory, names, files in os.walk(destination):
        os.chmod(directory, 0o755)
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(destination).as_posix()
            executable = (relative in executables if executables is not None
                          else seed is not None and os.access(Path(seed) / relative, os.X_OK))
            os.chmod(path, 0o755 if executable else 0o644)
            os.utime(path, (restored_at, restored_at), follow_symlinks=False)
    return destination


def strip_volatile(target):
    """Drop what is never reused: profile-root final outputs are re-linked from deps
    anyway, incremental state is off, and lock/tag files are per invocation."""
    target = Path(target)
    for name in ('.rustc_info.json', 'CACHEDIR.TAG', '.cargo-lock'):
        (target / name).unlink(missing_ok=True)
    for profile in [p for p in target.iterdir() if p.is_dir() and not p.is_symlink()]:
        for name in ('incremental', 'tmp', '.cargo-lock'):
            path = profile / name
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
    nextest = target / 'nextest'
    if nextest.is_dir():
        shutil.rmtree(nextest)
    return target


# --- archive ---------------------------------------------------------------------------

def target_inventory(root):
    """{relative path: [sha256, executable]} of a controller-owned target snapshot."""
    files = {}
    for directory, names, entries in os.walk(root):
        for name in names + entries:
            path = Path(directory) / name
            mode = os.lstat(path).st_mode
            if stat.S_ISDIR(mode) and name in names:
                continue
            if not stat.S_ISREG(mode):
                raise Unavailable('compile target contains a non-regular entry: ' + str(path.relative_to(root)))
            files[path.relative_to(root).as_posix()] = [sha256_file(path), bool(mode & 0o100)]
    return files


def pack(root, archive):
    """Deterministic gzip tar: sorted, fixed owner and time, 0755 for executables."""
    import gzip
    files = target_inventory(root)
    with archive.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=1,
                                                  mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name in sorted({str(p) for n in files for p in Path(n).parents if str(p) != '.'}):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 0
            tar.addfile(info)
        for name in sorted(files):
            path = root / name
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = path.stat().st_size, 0o755 if files[name][1] else 0o644, 0
            with path.open('rb') as stream:
                tar.addfile(info, stream)
    return files


def unpack(archive, destination, expected):
    """Regular files at verified relative paths, each equal to its manifest digest."""
    digests = {name: row[0] for name, row in expected.items()}
    units.unpack(archive, destination, digests)
    return destination


# --- identity and provenance --------------------------------------------------------------

def producer_kind(env=None):
    """'dev' or 'qa' for the protected pipelines that may write; None otherwise."""
    env = os.environ if env is None else env
    pair = (env.get('CI_PIPELINE_SOURCE'), env.get('CI_COMMIT_BRANCH'))
    if pair in (('push', 'dev'), ('schedule', 'dev')):
        return 'dev'
    if pair == ('push', 'qa') and env.get('CI_COMMIT_REF_PROTECTED') == 'true':
        return 'qa'
    return None


PRODUCER_PIPELINES = {('dev', 'push'), ('dev', 'schedule'), ('qa', 'push')}


def identity(job, image, checkout, target, env, *, target_triple=TARGET):
    """Everything outside the sources that decides a unit, beyond Cargo's own fingerprint.

    The job name separates the linted core-build target (clippy-driver wraps every
    unit) from unlinted ones; RUSTC_WRAPPER and CLIPPY_ARGS are keyed as well, so a
    cached unit can never satisfy a build with another compiler identity.
    """
    return {
        'schema': SCHEMA, 'job': job, 'image': image, 'target': target_triple,
        'checkout': str(checkout), 'target_dir': str(target), 'cargo_home': units.CARGO_HOME_PATH,
        'environment': {key: env.get(key) for key in (*ENVIRONMENT, 'CLIPPY_ARGS')},
    }


def provenance(registry, version, row, manifest):
    """The manifest and its archive were each uploaded once, by the producer's own
    protected dev/qa pipeline at the manifest's commit."""
    producer = manifest['producer']
    if (producer.get('ref'), producer.get('source')) not in PRODUCER_PIPELINES or producer.get('protected') is not True:
        raise Unavailable('compile target producer is not a protected dev/qa pipeline')
    files = registry.json(f"/packages/{row['package_id']}/package_files?per_page=100&order_by=created_at&sort=desc")
    for name, digest in ((row['file_name'], None), (manifest['archive']['name'], manifest['archive']['sha256'])):
        rows = [r for r in files if r.get('file_name') == name]
        if len(rows) != 1:
            raise Unavailable('compile target file is absent or duplicated: ' + name)
        pipelines = rows[0].get('pipelines') or []
        if [p.get('id') for p in pipelines] != [producer['pipeline_id']]:
            raise Unavailable('compile target file was not written by its producer pipeline')
        pipeline = pipelines[0]
        if (pipeline.get('ref'), pipeline.get('source')) != (producer['ref'], producer['source']) \
                or pipeline.get('sha') != producer['commit']:
            raise Unavailable('compile target producer pipeline differs from its manifest')
        if digest is not None and rows[0].get('file_sha256') != digest:
            raise Unavailable('registry digest differs from the compile target manifest')
    return {'pipeline_id': producer['pipeline_id'], 'commit': producer['commit'], 'ref': producer['ref']}


def candidates(registry, version, limit=5):
    """Newest manifests first: (package id, manifest file name) rows."""
    query = urllib.parse.urlencode({'package_type': 'generic', 'package_name': PACKAGE, 'package_version': version})
    packages = [p for p in registry.json('/packages?' + query)
                if p.get('name') == PACKAGE and p.get('version') == version]
    if len(packages) != 1:
        return []
    files = registry.json(f"/packages/{packages[0]['id']}/package_files?per_page=100&order_by=created_at&sort=desc")
    rows = [{'package_id': packages[0]['id'], 'file_name': row['file_name']} for row in files
            if re.fullmatch(r'manifest-[0-9a-f]{40}\.json', str(row.get('file_name')))]
    return rows[:limit]


# --- consumer ------------------------------------------------------------------------------

def job_identity(q):
    return identity(os.environ.get('CI_JOB_NAME'), q.execution.config['image'], q.root,
                    Path(q.env['CARGO_TARGET_DIR']), q.env)


def restore(q, registry=None, *, now=None):
    """Seed the job's CARGO_TARGET_DIR from the newest trusted target; never fail the job."""
    record = {'status': 'miss'}
    q.receipt['compile_target'] = record
    if q.execution is None or q.repository != 'GetBusbar/busbar':
        record['status'] = 'not-applicable'
        q.save()
        return None
    download = q.control / 'compile-target.tar.gz'
    target = Path(q.env['CARGO_TARGET_DIR'])
    started = time.monotonic()
    try:
        if target.exists() and any(target.iterdir()):
            raise Unavailable('job target is not empty')
        wanted = job_identity(q)
        version = key(wanted)
        record['key'] = version
        registry = registry or units.Registry(os.environ['CI_JOB_TOKEN'], package=PACKAGE)
        reasons = []
        for row in candidates(registry, version):
            try:
                manifest = json.loads(registry.read(version, row['file_name'], units.MAX_MANIFEST_BYTES))
                if manifest.get('schema') != SCHEMA or manifest.get('key') != version \
                        or manifest.get('identity') != wanted:
                    raise Unavailable('compile target manifest identity differs')
                if not isinstance(manifest.get('generation'), int) or not 0 <= manifest['generation'] < MAX_GENERATIONS:
                    raise Unavailable('compile target generation chain is exhausted')
                archive = manifest['archive']
                if not (isinstance(archive.get('bytes'), int) and 0 < archive['bytes'] <= MAX_ARCHIVE_BYTES
                        and re.fullmatch('[0-9a-f]{64}', archive.get('sha256', ''))
                        and archive.get('name') == 'target-' + archive['sha256'] + '.tar.gz'):
                    raise Unavailable('compile target archive is invalid')
                record['provenance'] = provenance(registry, version, row, manifest)
                break
            except (Unavailable, KeyError, TypeError, ValueError) as error:
                reasons.append(str(error)[:200])
        else:
            record['reasons'] = reasons[:5]
            return None
        registry.download(version, archive['name'], download, archive['bytes'], archive['sha256'])
        # One copy only: the job store also holds the build. Extract straight into
        # the empty job target, every file checked against the manifest digest.
        if target.exists():
            target.rmdir()
        unpack(download, target, manifest['files'])
        download.unlink()
        executables = {name for name, row in manifest['files'].items() if row[1]}
        restored_at = (time.time() if now is None else now) - 60
        settle(target, restored_at, executables)
        record['stamp'] = stamp_checkout(q.root, manifest['sources'], restored_at)
        record.update(status='hit', generation=manifest['generation'], archive_sha256=archive['sha256'],
                      archive_bytes=archive['bytes'], files=len(manifest['files']),
                      producer_commit=manifest['producer']['commit'])
        return manifest
    except (Unavailable, KeyError, TypeError, ValueError, OSError, tarfile.TarError) as error:
        record.update(status='fallback', reason=str(error)[:500])
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(exist_ok=True)
        return None
    finally:
        record['restore_seconds'] = round(time.monotonic() - started, 3)
        download.unlink(missing_ok=True)
        q.save()


# --- producer ------------------------------------------------------------------------------

def produce(q, restored=None, registry=None):
    """Publish this successful protected job's target; any failure is only recorded."""
    record = {'status': 'skipped'}
    q.receipt['compile_target_produced'] = record
    kind = producer_kind()
    if q.execution is None or q.repository != 'GetBusbar/busbar' or kind is None \
            or q.receipt.get('commit_ref_protected') is not True:
        q.save()
        return record
    owned = q.control / 'compile-target-out'
    archive_tmp = q.control / 'compile-target-out.tar.gz'
    started = time.monotonic()
    try:
        from check import copy_candidate_tree
        target = Path(q.env['CARGO_TARGET_DIR'])
        wanted = job_identity(q)
        version = key(wanted)
        copy_candidate_tree(target, owned)
        strip_volatile(owned)
        files = pack(owned, archive_tmp)
        digest = sha256_file(archive_tmp)
        if archive_tmp.stat().st_size > MAX_ARCHIVE_BYTES:
            raise Unavailable('compile target exceeds its archive bound')
        commit = os.environ['CI_COMMIT_SHA']
        archive = {'name': 'target-' + digest + '.tar.gz', 'sha256': digest, 'bytes': archive_tmp.stat().st_size}
        manifest = {'schema': SCHEMA, 'key': version, 'identity': wanted, 'archive': archive, 'files': files,
                    'sources': source_inventory(q.root),
                    'generation': 0 if restored is None else restored['generation'] + 1,
                    'producer': {'pipeline_id': int(os.environ['CI_PIPELINE_ID']), 'job_id': int(os.environ['CI_JOB_ID']),
                                 'commit': commit, 'ref': os.environ.get('CI_COMMIT_BRANCH'),
                                 'source': os.environ.get('CI_PIPELINE_SOURCE'), 'protected': True}}
        manifest_path = q.control / 'compile-target-manifest.json'
        manifest_path.write_bytes(canonical(manifest))
        registry = registry or units.Registry(os.environ['CI_JOB_TOKEN'], package=PACKAGE)
        # The archive first; the manifest is the marker consumers look for.
        registry.upload(version, archive['name'], archive_tmp)
        registry.upload(version, 'manifest-' + commit + '.json', manifest_path)
        record.update(status='published', key=version, generation=manifest['generation'],
                      archive_sha256=digest, archive_bytes=archive['bytes'], files=len(files))
    except Exception as error:  # an optimisation: never fail the qualified job
        record.update(status='failed', reason=str(error)[:500])
    finally:
        record['seconds'] = round(time.monotonic() - started, 3)
        shutil.rmtree(owned, ignore_errors=True)
        archive_tmp.unlink(missing_ok=True)
        q.save()
    return record
