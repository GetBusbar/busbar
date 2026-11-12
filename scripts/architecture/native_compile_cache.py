"""Trusted core compile target: a protected job's Cargo target dir, restored by later runs.

Applicable jobs: core-build (the plain certified release build) and core-clippy
(the lint-only job), the jobs that compile the root and dist/default graphs in
both the DEV and QA tiers. Between two commits almost every unit is identical:
all third-party units, and every workspace crate the change does not reach.
Each job has its own key (the job name and its exact command recipe are keyed),
so linted units never meet the certified build's units.

Fixed paths: both jobs run their candidate invocations with the checkout and the
job's candidate directory mounted at native_confinement.FIXED_ROOTS, so the
paths a compiler sees (and Cargo fingerprints) are the same in every job. The
key contains those container paths, never a host path with a job id.

Producer: a successful applicable job of a protected tier pipeline
(native_release_stage.cache_producer: protected dev push, protected qa push, the
owner's protected dev schedule; never a merge request, API run or plugin). After
the job's last candidate step the controller snapshots CARGO_TARGET_DIR plus a
content inventory of the exact source tree, and publishes both to core's generic
package registry under a key over everything outside the sources that decides
Cargo unit identity (toolchain, image, target, compile environment, command
recipe, fixed checkout/target/Cargo home paths), computed once when the build
environment is final and required unchanged at publication. A commit already
published under the key is not published again; the producer keeps only the
newest RETAIN entries of its key and deletes older ones from this package only.

Generations: a producer that restored a previous target records generation
parent + 1. The consumer looks only at the newest valid entry's generation: at
MAX_GENERATIONS it starts cold (never falling back to an older entry), so at most
MAX_GENERATIONS consecutive producers inherit units from one cold build.

Consumer: the same key, protected provenance (writing pipeline, ref, source,
commit, manifest name), archive and per-file digests, extraction straight into the
job's empty CARGO_TARGET_DIR. Anything absent or doubtful starts from an empty
target as before.

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
# consumer that finds the newest entry at this generation starts cold, so at most
# this many producers ever inherit units from one cold build.
MAX_GENERATIONS = 16
# Entries (manifest + archive) kept per key; older ones are deleted by the producer.
RETAIN = 3
MANIFEST_NAME = re.compile(r'manifest-([0-9a-f]{40})-([1-9][0-9]*)\.json')
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


def settle(destination, restored_at, executables):
    """Writable modes, execute bits and one restore time on an extracted target.

    Build-script and test executables (named by the verified manifest) keep their
    execute bit: Cargo runs a restored build script whenever its inputs differ.
    """
    for directory, names, files in os.walk(destination):
        os.chmod(directory, 0o755)
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(destination).as_posix()
            os.chmod(path, 0o755 if relative in executables else 0o644)
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
    """'dev' or 'qa' for the protected tier pipelines that may write; None otherwise."""
    from native_release_stage import cache_producer
    return cache_producer(os.environ if env is None else env)


def identity(job, image, checkout, target, env, recipe, *, target_triple=TARGET):
    """Everything outside the sources that decides a unit, beyond Cargo's own fingerprint.

    checkout and target are the fixed in-container paths. The job name and its
    exact command recipe separate the lint-only core-clippy target from the
    certified build's; RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER and CLIPPY_ARGS of
    the final build environment are keyed as well.
    """
    return {
        'schema': SCHEMA, 'job': job, 'image': image, 'target': target_triple,
        'checkout': str(checkout), 'target_dir': str(target), 'cargo_home': units.CARGO_HOME_PATH,
        'environment': {key: env.get(key) for key in (*ENVIRONMENT, 'CLIPPY_ARGS')},
        'recipe': recipe,
    }


def archive_name(pipeline_id, sha256):
    """Per producing pipeline too: two producers of identical bytes never share a file name."""
    return f'target-{int(pipeline_id)}-{sha256}.tar.gz'


def manifest_name(commit, pipeline_id):
    """One name per producing pipeline: a dev and a qa run of one commit never collide."""
    return f'manifest-{commit}-{int(pipeline_id)}.json'


def provenance(registry, row, manifest):
    """The manifest and its archive were each uploaded once, by the producer's own
    protected tier pipeline at the manifest's commit, under the producer's name."""
    from native_release_stage import CACHE_PRODUCER_PIPELINES
    producer = manifest['producer']
    if (producer.get('source'), producer.get('ref')) not in CACHE_PRODUCER_PIPELINES \
            or producer.get('protected') is not True:
        raise Unavailable('compile target producer is not a protected tier pipeline')
    if row['file_name'] != manifest_name(producer.get('commit'), producer.get('pipeline_id')):
        raise Unavailable('compile target manifest name differs from its producer')
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


def package(registry, version):
    """(package id, newest-first file rows) of this key's package version, or (None, [])."""
    query = urllib.parse.urlencode({'package_type': 'generic', 'package_name': PACKAGE, 'package_version': version})
    packages = [p for p in registry.json('/packages?' + query)
                if p.get('name') == PACKAGE and p.get('version') == version]
    if len(packages) != 1:
        return None, []
    rows = []
    for page in range(1, 11):
        batch = registry.json(f"/packages/{packages[0]['id']}/package_files"
                              f"?per_page=100&page={page}&order_by=created_at&sort=desc")
        rows.extend(batch)
        if len(batch) < 100:
            break
    return packages[0]['id'], rows


def candidates(registry, version, limit=5):
    """Newest manifests first: (package id, manifest file name) rows."""
    package_id, files = package(registry, version)
    rows = [{'package_id': package_id, 'file_name': row['file_name']} for row in files
            if MANIFEST_NAME.fullmatch(str(row.get('file_name')))]
    return rows[:limit]


def retain(registry, version, keep=RETAIN):
    """Delete this key's entries beyond the newest `keep`; this package only.

    An entry is a manifest and every file its producing pipeline uploaded to
    this key. A pipeline whose manifest is not yet present (an upload in
    flight) is never touched. Returns the deleted file names.
    """
    if getattr(registry, 'package', None) != PACKAGE:
        raise Unavailable('retention runs only on the compile target package')
    package_id, files = package(registry, version)
    if package_id is None:
        return []
    manifests = [(row, MANIFEST_NAME.fullmatch(str(row.get('file_name')))) for row in files]
    manifests = [(row, match) for row, match in manifests if match]
    expired = {int(match[2]) for _, match in manifests[keep:]}
    expired -= {int(match[2]) for _, match in manifests[:keep]}
    deleted = []
    for row in files:
        writers = {p.get('id') for p in row.get('pipelines') or []}
        if len(writers) == 1 and writers <= expired and type(row.get('id')) is int:
            registry.delete_package_file(package_id, row['id'])
            deleted.append(row['file_name'])
    return deleted


# --- consumer ------------------------------------------------------------------------------

def job_identity(q, recipe):
    """This job's identity from its final build environment, on fixed container roots."""
    execution = q.execution
    if not getattr(execution, 'fixed_paths', None):
        raise Unavailable('compile target requires fixed in-container checkout and target roots')
    return identity(os.environ.get('CI_JOB_NAME'), execution.config['image'], execution.container_path(q.root),
                    execution.container_path(q.env['CARGO_TARGET_DIR']), q.env, recipe)


def restore(q, recipe, registry=None, *, now=None):
    """Seed the job's CARGO_TARGET_DIR from the newest trusted target; never fail the job.

    Call once the job's build environment is final: the identity computed here is
    the one produce() requires again before publishing.
    """
    record = {'status': 'miss'}
    q.receipt['compile_target'] = record
    q.compile_target_identity = None
    if q.execution is None or q.repository != 'GetBusbar/busbar' or recipe is None:
        record['status'] = 'not-applicable'
        q.save()
        return None
    download = q.control / 'compile-target.tar.gz'
    target = Path(q.env['CARGO_TARGET_DIR'])
    started = time.monotonic()
    try:
        if target.exists() and any(target.iterdir()):
            raise Unavailable('job target is not empty')
        wanted = job_identity(q, recipe)
        version = key(wanted)
        q.compile_target_identity = wanted
        record['key'] = version
        registry = registry or units.Registry(os.environ['CI_JOB_TOKEN'], package=PACKAGE)
        reasons, manifest = [], None
        for row in candidates(registry, version):
            try:
                found = json.loads(registry.read(version, row['file_name'], units.MAX_MANIFEST_BYTES))
                if found.get('schema') != SCHEMA or found.get('key') != version \
                        or found.get('identity') != wanted:
                    raise Unavailable('compile target manifest identity differs')
                archive = found['archive']
                if not (isinstance(archive.get('bytes'), int) and 0 < archive['bytes'] <= MAX_ARCHIVE_BYTES
                        and re.fullmatch('[0-9a-f]{64}', archive.get('sha256', ''))
                        and archive.get('name') == archive_name(found['producer']['pipeline_id'], archive['sha256'])):
                    raise Unavailable('compile target archive is invalid')
                provenance_record = provenance(registry, row, found)
            except (Unavailable, KeyError, TypeError, ValueError) as error:
                reasons.append(str(error)[:200])
                continue
            # The newest valid entry decides: an exhausted chain starts cold and
            # never falls back to an older, lower-generation entry.
            if not isinstance(found.get('generation'), int) or not 0 <= found['generation'] < MAX_GENERATIONS:
                reasons.append('compile target generation chain is exhausted')
                break
            manifest, record['provenance'] = found, provenance_record
            break
        if manifest is None:
            record['reasons'] = reasons[:5]
            return None
        archive = manifest['archive']
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

def produce(q, restored, recipe, registry=None):
    """Publish this successful protected job's target; any failure is only recorded."""
    record = {'status': 'skipped'}
    q.receipt['compile_target_produced'] = record
    kind = producer_kind()
    if q.execution is None or q.repository != 'GetBusbar/busbar' or kind is None or recipe is None \
            or q.receipt.get('commit_ref_protected') is not True:
        q.save()
        return record
    owned = q.control / 'compile-target-out'
    archive_tmp = q.control / 'compile-target-out.tar.gz'
    started = time.monotonic()
    try:
        from check import copy_candidate_tree
        target = Path(q.env['CARGO_TARGET_DIR'])
        wanted = job_identity(q, recipe)
        if wanted != getattr(q, 'compile_target_identity', None):
            raise Unavailable('build environment changed after the compile target key was computed')
        version = key(wanted)
        commit, pipeline_id = os.environ['CI_COMMIT_SHA'], int(os.environ['CI_PIPELINE_ID'])
        registry = registry or units.Registry(os.environ['CI_JOB_TOKEN'], package=PACKAGE)
        _, existing = package(registry, version)
        present = sorted(row['file_name'] for row in existing
                         if (match := MANIFEST_NAME.fullmatch(str(row.get('file_name')))) and match[1] == commit)
        if present:
            # Same key and same commit: an equivalent entry already exists.
            record.update(status='present', key=version, existing=present[:3])
            return record
        copy_candidate_tree(target, owned)
        strip_volatile(owned)
        files = pack(owned, archive_tmp)
        digest = sha256_file(archive_tmp)
        if archive_tmp.stat().st_size > MAX_ARCHIVE_BYTES:
            raise Unavailable('compile target exceeds its archive bound')
        archive = {'name': archive_name(pipeline_id, digest), 'sha256': digest, 'bytes': archive_tmp.stat().st_size}
        manifest = {'schema': SCHEMA, 'key': version, 'identity': wanted, 'archive': archive, 'files': files,
                    'sources': source_inventory(q.root),
                    'generation': 0 if restored is None else restored['generation'] + 1,
                    'producer': {'pipeline_id': pipeline_id, 'job_id': int(os.environ['CI_JOB_ID']),
                                 'commit': commit, 'ref': os.environ.get('CI_COMMIT_BRANCH'),
                                 'source': os.environ.get('CI_PIPELINE_SOURCE'), 'protected': True,
                                 'tier': kind}}
        manifest_path = q.control / 'compile-target-manifest.json'
        manifest_path.write_bytes(canonical(manifest))
        # The archive first; the manifest is the marker consumers look for.
        registry.upload(version, archive['name'], archive_tmp)
        registry.upload(version, manifest_name(commit, pipeline_id), manifest_path)
        record.update(status='published', key=version, generation=manifest['generation'],
                      archive_sha256=digest, archive_bytes=archive['bytes'], files=len(files))
        try:
            record['retention'] = {'keep': RETAIN, 'deleted': retain(registry, version)}
        except Exception as error:  # retention never undoes a publication
            record['retention'] = {'keep': RETAIN, 'error': str(error)[:300]}
    except Exception as error:  # an optimisation: never fail the qualified job
        record.update(status='failed', reason=str(error)[:500])
    finally:
        record['seconds'] = round(time.monotonic() - started, 3)
        shutil.rmtree(owned, ignore_errors=True)
        archive_tmp.unlink(missing_ok=True)
        q.save()
    return record
