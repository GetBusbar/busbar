"""Trusted prebuilt product test images: the pinned plugin cdylibs of product-inputs.

core's product-inputs step (scripts/ci-product-inputs.sh -> product_artifacts.py)
builds one dev-profile cdylib per vector product that declares test artifacts.
These are pinned products, not candidate code: each is a pure function of the
product commit and lock, the toolchain, the image, the compile environment and
the Cargo configuration discovered from the candidate root (cargo runs there).

Producer: the core dev push dependency-unit producer shard that owns a product
runs product_artifacts.build_image -- the same image_argv() the consumer would
run -- in the ordinary candidate confinement, and publishes the image to core's
generic package registry under a key over every one of those inputs.

An owner API pipeline on the protected native_dep_cache.PINNED_REF produces the
same images under a key that also carries the pinned-producer marker (that exact
core commit), like dependency units: they never share a key with dev producers
and match only a consumer qualifying against exactly that host revision.

Consumer: core native qualification computes the same key (and, on a miss, the
pinned key for its host revision). A verified hit (protected dev-push or pinned
owner-pipeline provenance, archive and file digests) is staged into a
controller-owned read-only directory that only the product-inputs step mounts;
the trusted script verifies the digest again and copies it to the exact path
Cargo would have written. Anything absent, different or doubtful builds as
before. The candidate's packer is never prebuilt. After the step the controller
requires every restored image to be byte-identical at its bound path.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import time

import native_dep_cache as units
from native_dep_cache import Unavailable, canonical, key, sha256_file

SCHEMA = 'busbar.product-test-image/1'
PACKAGE = 'busbar-product-test-images'
MAX_IMAGE_BYTES = 512 * 1024**2
TARGET = 'x86_64-unknown-linux-gnu'
# Controller environment that reaches rustc, Cargo or a product build script's
# unit identity, plus CI (build scripts may read it). Absent keys are null.
ENVIRONMENT = (*units.COMPILE_ENV, 'CI')
WORKERS = 8


def cargo_configuration(root):
    """Digests of every Cargo configuration file cargo discovers from root.

    Cargo reads `.cargo/config(.toml)` in the invocation directory and each
    ancestor. The candidate root's files are keyed; any ancestor configuration
    is unexpected on the controller layout and is a miss.
    """
    root = Path(root)
    rows = {}
    for relative in ('.cargo/config.toml', '.cargo/config'):
        path = root / relative
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise Unavailable('indirect Cargo configuration: ' + relative)
        rows[relative] = sha256_file(path) if path.is_file() else None
    for parent in root.resolve().parents:
        if (parent / '.cargo').exists():
            raise Unavailable('Cargo configuration above the build root')
    return rows


def builder_sha256(trusted):
    """The trusted recipe: product_artifacts.py and the product-inputs wrapper."""
    rows = []
    for relative in ('scripts/architecture/product_artifacts.py', 'scripts/ci-product-inputs.sh'):
        path = Path(trusted) / relative
        rows.append([relative, sha256_file(path) if path.is_file() else None])
    return key(rows)


def seed_configuration(execution):
    seed = getattr(execution, 'dependency_seed', None)
    if seed is None:
        return None
    path = Path(seed) / 'config.toml'
    return sha256_file(path) if path.is_file() else None


def identity(row, sdk, image, env, cargo_config, builder, seed_config, pinned_commit=None):
    """Everything outside the product commit that decides the image bytes.

    A pinned-ref producer adds its exact core commit (as native_dep_cache does).
    """
    value = {
        'schema': SCHEMA,
        'repository': 'GetBusbar/' + row['repo'],
        'commit': row['commit'],
        'package': row['package'],
        'image_name': row['image'],
        'lock_sha256': row['lock_sha256'],
        'sdk': sdk,
        'image': image,
        'target': TARGET,
        'cargo_home': units.CARGO_HOME_PATH,
        'cargo_home_config_sha256': seed_config,
        'environment': {name: env.get(name) for name in ENVIRONMENT},
        'cargo_configuration': cargo_config,
        'builder_sha256': builder,
    }
    if pinned_commit is not None:
        value['pinned_producer'] = {'ref': units.PINNED_REF, 'commit': pinned_commit}
    return value


def job_identity(q, row, sdk, pinned_commit=None):
    return identity(row, sdk, q.execution.config['image'], q.env, cargo_configuration(q.root),
                    builder_sha256(q.trusted), seed_configuration(q.execution), pinned_commit)


def planned(q, vector, revision):
    """The products product-inputs builds, read from exact canonical commits."""
    from native_product_inputs import canonical_plan
    products, _ = canonical_plan(q.work, q.policy, vector, revision)
    return products


# --- Consumer ------------------------------------------------------------------------

def restore_one(q, row, sdk, registry, staging):
    record = {'status': 'miss'}
    try:
        wanted = job_identity(q, row, sdk)
        version = key(wanted)
        record['key'] = version
        try:
            manifest = json.loads(registry.read(version, units.MANIFEST, units.MAX_MANIFEST_BYTES))
        except FileNotFoundError:
            # Only on a dev-key miss: the owner-run producer's image for exactly
            # the core host revision this job qualifies against.
            host = q.receipt.get('host_revision')
            if not (isinstance(host, str) and re.fullmatch('[0-9a-f]{40}', host)):
                return record, None
            wanted = job_identity(q, row, sdk, pinned_commit=host)
            version = key(wanted)
            record['pinned_key'] = version
            try:
                manifest = json.loads(registry.read(version, units.MANIFEST, units.MAX_MANIFEST_BYTES))
            except FileNotFoundError:
                return record, None
        if manifest.get('schema') != SCHEMA or manifest.get('key') != version or manifest.get('identity') != wanted:
            raise Unavailable('image manifest identity differs')
        archive, image = manifest['archive'], manifest['image']
        if not (isinstance(archive.get('bytes'), int) and 0 < archive['bytes'] <= MAX_IMAGE_BYTES
                and re.fullmatch('[0-9a-f]{64}', archive.get('sha256', ''))
                and archive.get('name') == 'image-' + archive['sha256'] + '.tar.gz'
                and re.fullmatch('[0-9a-f]{64}', image.get('sha256', ''))
                and manifest.get('files') == {row['image']: image['sha256']}):
            raise Unavailable('image manifest archive is invalid')
        record['provenance'] = units.provenance(registry, version, manifest)
        download = staging / (row['repo'] + '.tar.gz')
        destination = staging / row['repo']
        try:
            registry.download(version, archive['name'], download, archive['bytes'], archive['sha256'])
            units.unpack(download, destination, manifest['files'])
        finally:
            download.unlink(missing_ok=True)
        if sha256_file(destination / row['image']) != image['sha256']:
            raise Unavailable('image digest differs from its manifest')
        record.update(status='hit', sha256=image['sha256'], bytes=image['bytes'])
        return record, {'commit': row['commit'], 'image': row['image'], 'lock_sha256': row['lock_sha256'],
                        'file': row['repo'] + '/' + row['image'], 'sha256': image['sha256'], 'key': version}
    except (Unavailable, KeyError, TypeError, ValueError, OSError, tarfile.TarError) as error:
        record.update(status='fallback', reason=str(error)[:500])
        shutil.rmtree(staging / row['repo'], ignore_errors=True)
        return record, None


def restore(q, vector, revision, registry=None):
    """Stage verified images read-only for product-inputs; return their index."""
    record = {'status': 'not-applicable', 'products': {}}
    q.receipt['product_images'] = record
    if q.execution is None:
        q.save()
        return {}
    started = time.monotonic()
    staging = q.control / 'product-images'
    index = {}
    try:
        products = planned(q, vector, revision)
        registry = registry or units.Registry(os.environ['CI_JOB_TOKEN'], package=PACKAGE)
        staging.mkdir(mode=0o700)
        rows = [item['product'] for item in products]
        with ThreadPoolExecutor(max_workers=max(1, min(WORKERS, len(rows)))) as pool:
            results = list(pool.map(lambda row: restore_one(q, row, vector['sdk'], registry, staging), rows))
        for row, (result, entry) in zip(rows, results):
            record['products'][row['repo']] = result
            if entry is not None:
                index[row['repo']] = entry
        (staging / 'index.json').write_bytes(canonical(index))
        units.seal(staging)
        q.execution.product_images = units.readonly_seed(staging, q.execution)
        hits = len(index)
        record['status'] = 'hit' if hits == len(rows) and rows else ('partial' if hits else 'miss')
    except (Unavailable, KeyError, TypeError, ValueError, OSError) as error:
        record.update(status='fallback', reason=str(error)[:500])
        discard(q)
        index = {}
    record['restore_seconds'] = round(time.monotonic() - started, 3)
    q.save()
    return index


def verify(q, index, products):
    """Every restored image must still be the trusted bytes at its bound path."""
    from check import Violation
    from native import candidate_output
    import hashlib
    images = {item['product']['repo']: Path(item['image']) for item in products}
    for repo, entry in sorted(index.items()):
        hasher = hashlib.sha256()
        with candidate_output(q, images[repo], MAX_IMAGE_BYTES, compiler_output=True) as (stream, _):
            while chunk := stream.read(1024**2):
                hasher.update(chunk)
        if hasher.hexdigest() != entry['sha256']:
            raise Violation('restored product image changed during product preparation: ' + repo)
        q.receipt['product_images']['products'][repo]['verified_after_step'] = True
    q.save()


def discard(q):
    if q.execution is not None:
        q.execution.product_images = None
    staging = q.control / 'product-images'
    if staging.exists():
        units.discard(staging)


# --- Producer ------------------------------------------------------------------------

def produce_image(q, row, vector, registry, *, upload=True, pinned_commit=None):
    """Build one pinned product's test image with the consumer's exact recipe."""
    from native import collect_output
    wanted = job_identity(q, row, vector['sdk'], pinned_commit)
    version = key(wanted)
    result = {'repo': row['repo'], 'commit': row['commit'], 'key': version, 'kind': 'image'}
    try:
        registry.read(version, units.MANIFEST, units.MAX_MANIFEST_BYTES)
        result['status'] = 'present'
        return result
    except FileNotFoundError:
        pass
    # One shard-wide target, exactly like the consumer's shared CARGO_TARGET_DIR:
    # a unit another product already built has the same metadata and bytes.
    target = q.work / 'product-images-target'
    stdout = q.run('product-image-' + row['repo'],
                   ['python3', str(q.trusted / 'scripts/architecture/product_artifacts.py'),
                    '--root', str(q.root), '--target', str(target), '--cache', q.env['MODERNCI_CACHE_DIR'],
                    '--image-only', row['repo']], cwd=q.root)
    built = Path(stdout.read_text().strip())
    if built.name != row['image'] or built.parent != target / 'debug':
        raise Unavailable('producer image path differs from the consumer binding')
    owned = q.control / 'product-images-out' / row['repo']
    shutil.rmtree(owned, ignore_errors=True)
    owned.mkdir(parents=True)
    collect_output(q, built, owned / row['image'], limit=MAX_IMAGE_BYTES, compiler_output=True)
    image = {'sha256': sha256_file(owned / row['image']), 'bytes': (owned / row['image']).stat().st_size}
    archive_tmp = owned.parent / (row['repo'] + '.tar.gz')
    files = units.pack(owned, archive_tmp)
    digest = sha256_file(archive_tmp)
    archive = {'name': 'image-' + digest + '.tar.gz', 'sha256': digest, 'bytes': archive_tmp.stat().st_size}
    manifest = {'schema': SCHEMA, 'key': version, 'identity': wanted, 'archive': archive, 'files': files,
                'image': image, 'product': {'repo': row['repo'], 'commit': row['commit']},
                'producer': {'pipeline_id': int(os.environ['CI_PIPELINE_ID']), 'job_id': int(os.environ['CI_JOB_ID']),
                             'commit': os.environ['CI_COMMIT_SHA'], 'ref': os.environ.get('CI_COMMIT_BRANCH'),
                             'source': os.environ.get('CI_PIPELINE_SOURCE'),
                             'protected': os.environ.get('CI_COMMIT_REF_PROTECTED') == 'true'}}
    manifest_path = owned.parent / (row['repo'] + '.manifest.json')
    manifest_path.write_bytes(canonical(manifest))
    result.update(status='built', sha256=image['sha256'], bytes=image['bytes'])
    if upload:
        # The archive first; the manifest is the commit marker consumers look for.
        registry.upload(version, archive['name'], archive_tmp)
        registry.upload(version, units.MANIFEST, manifest_path)
        result['status'] = 'published'
    shutil.rmtree(owned)
    archive_tmp.unlink()
    manifest_path.unlink()
    return result


def produce(q, rows, registry=None, *, pinned_commit=None):
    """Called by the dependency-unit producer for its shard's products only.

    pinned_commit is the pinned owner pipeline's own core commit, else None.
    """
    registry = registry or units.Registry(os.environ['CI_JOB_TOKEN'], package=PACKAGE)
    vector = json.loads((q.root / 'scripts/ci-product-pins.json').read_text())
    declared = {item['product']['repo'] for item in planned(q, vector, q.receipt['source'])}
    results = []
    for row in rows:
        if row['repo'] not in declared:
            continue
        try:
            results.append(produce_image(q, row, vector, registry, pinned_commit=pinned_commit))
        except Exception as error:  # one product's failure must not block the others
            results.append({'repo': row['repo'], 'kind': 'image', 'status': 'failed', 'reason': str(error)[:500]})
        q.receipt['product_images_produced'] = results
        q.save()
    return results
