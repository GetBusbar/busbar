"""Trusted core compile target: content-stamped reuse, identity and provenance."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import native_compile_cache as cache
from native_dep_cache import Unavailable, key


def tree(root, files):
    for name, data in files.items():
        path = Path(root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


class Stamping(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name) / 'checkout'
        tree(self.root, {'Cargo.toml': b'[workspace]\n', 'Cargo.lock': b'# lock\n',
                         'crates/a/src/lib.rs': b'pub fn a() {}\n', 'crates/b/src/lib.rs': b'pub fn b() {}\n',
                         'crates/b/src/extra.rs': b'// extra\n', 'target/debug/x': b'out',
                         '.git/HEAD': b'ref\n'})
        # The producer's checkout is older than its restored units.
        for directory, names, files in os.walk(self.root):
            for name in names + files:
                os.utime(Path(directory) / name, ns=(1_700_000_000_123_456_789,) * 2)
        os.utime(self.root, ns=(1_700_000_000_123_456_789,) * 2)
        self.produced = cache.source_inventory(self.root)
        self.restored = time.time() - 60

    def tearDown(self):
        self.dir.cleanup()

    def mtime(self, relative):
        return os.lstat(self.root / relative if relative else self.root).st_mtime_ns

    PRODUCED = 1_700_000_000_123_456_789

    def test_inventory_excludes_vcs_and_cargo_output(self):
        self.assertNotIn('target/debug/x', self.produced['files'])
        self.assertNotIn('.git/HEAD', self.produced['files'])
        self.assertIn('crates/a/src/lib.rs', self.produced['files'])

    def test_unchanged_sources_are_older_than_restored_units(self):
        decision = cache.stamp_checkout(self.root, self.produced, self.restored)
        self.assertEqual(decision['changed_files'], 0)
        self.assertFalse(decision['all_workspace_units_rebuild'])
        # Cargo compares a build script's newest package mtime for equality: exact times.
        for relative in ('crates/a/src/lib.rs', 'crates/b', ''):
            self.assertEqual(self.mtime(relative), self.PRODUCED)

    def test_changed_and_added_paths_postdate_restored_units(self):
        (self.root / 'crates/a/src/lib.rs').write_bytes(b'pub fn a() { changed() }\n')
        (self.root / 'crates/b/src/new.rs').write_bytes(b'// new\n')
        decision = cache.stamp_checkout(self.root, self.produced, self.restored)
        self.assertFalse(decision['all_workspace_units_rebuild'])
        restored = self.restored * 1e9
        self.assertGreater(self.mtime('crates/a/src/lib.rs'), restored)
        self.assertGreater(self.mtime('crates/b/src/new.rs'), restored)
        # The directory that gained an entry is new; its unchanged siblings keep their time.
        self.assertGreater(self.mtime('crates/b/src'), restored)
        self.assertEqual(self.mtime('crates/b/src/lib.rs'), self.PRODUCED)
        self.assertEqual(self.mtime('crates/a'), self.PRODUCED)

    def test_a_removed_file_rebuilds_every_workspace_unit(self):
        # Cargo's newest-mtime package scan cannot see a deletion; be stricter than Cargo.
        (self.root / 'crates/b/src/extra.rs').unlink()
        decision = cache.stamp_checkout(self.root, self.produced, self.restored)
        self.assertEqual(decision['removed_files'], 1)
        self.assertTrue(decision['all_workspace_units_rebuild'])
        self.assertGreater(self.mtime('crates/a/src/lib.rs'), self.restored * 1e9)

    def test_same_bytes_at_a_new_time_are_unchanged(self):
        path = self.root / 'crates/a/src/lib.rs'
        os.utime(path, (time.time(), time.time()))
        cache.stamp_checkout(self.root, self.produced, self.restored)
        self.assertEqual(self.mtime('crates/a/src/lib.rs'), self.PRODUCED)

    def test_manifest_lock_or_cargo_config_change_rebuilds_every_workspace_unit(self):
        for name in ('Cargo.lock', 'crates/a/Cargo.toml', '.cargo/config.toml', 'rust-toolchain.toml'):
            with self.subTest(name=name):
                tree(self.root, {name: b'changed\n'})
                decision = cache.stamp_checkout(self.root, self.produced, self.restored)
                self.assertTrue(decision['all_workspace_units_rebuild'])
                self.assertGreater(self.mtime('crates/b/src/lib.rs'), self.restored * 1e9)
                (self.root / name).unlink() if name != 'Cargo.lock' else (self.root / name).write_bytes(b'# lock\n')

    def test_special_files_make_the_tree_unusable(self):
        os.mkfifo(self.root / 'crates/a/pipe')
        with self.assertRaisesRegex(Unavailable, 'special file'):
            cache.source_inventory(self.root)

    def test_restored_units_must_postdate_every_producer_source(self):
        with self.assertRaises(Unavailable):
            cache.stamp_checkout(self.root, self.produced, cache.OLD - 10)
        with self.assertRaisesRegex(Unavailable, 'postdate'):
            cache.stamp_checkout(self.root, self.produced, 1_700_000_000)


class Archive(unittest.TestCase):
    def test_executables_survive_pack_unpack_settle(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / 'target'
            tree(target, {'debug/build/x-1/build-script-build': b'#!/bin/sh\n', 'debug/deps/liba.rlib': b'rlib'})
            os.chmod(target / 'debug/build/x-1/build-script-build', 0o755)
            os.chmod(target / 'debug/deps/liba.rlib', 0o644)
            files = cache.pack(target, base / 'a.tar.gz')
            self.assertEqual(files['debug/build/x-1/build-script-build'][1], True)
            self.assertEqual(files['debug/deps/liba.rlib'][1], False)
            restored_target = cache.unpack(base / 'a.tar.gz', base / 'job-target', files)
            restored = time.time() - 60
            cache.settle(restored_target, restored, {name for name, row in files.items() if row[1]})
            self.assertTrue(os.access(restored_target / 'debug/build/x-1/build-script-build', os.X_OK))
            self.assertFalse(os.access(restored_target / 'debug/deps/liba.rlib', os.X_OK))
            self.assertEqual(int(os.stat(restored_target / 'debug/deps/liba.rlib').st_mtime), int(restored))

    def test_tampered_archive_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tree(base / 'target', {'debug/deps/liba.rlib': b'rlib'})
            files = cache.pack(base / 'target', base / 'a.tar.gz')
            files['debug/deps/liba.rlib'][0] = '0' * 64
            with self.assertRaises(Unavailable):
                cache.unpack(base / 'a.tar.gz', base / 'seed', files)


BUILD_RECIPE = {'commands': [['cargo', 'build', '--release']], 'rustc_wrapper': ''}
CLIPPY_RECIPE = {'commands': [['cargo', 'clippy', '--', '-D', 'warnings']], 'linter': 'cargo clippy'}


class Identity(unittest.TestCase):
    ENV = {'RUSTUP_TOOLCHAIN': '1.98.0', 'CARGO_INCREMENTAL': '0'}

    def value(self, job='core-build', recipe=BUILD_RECIPE, **env):
        return key(cache.identity(job, 'sha256:' + 'a' * 64, '/__busbar_checkout', '/__busbar_candidate/target',
                                  dict(self.ENV, **env), recipe))

    def test_compiler_identity_recipe_and_lint_arguments_are_keyed(self):
        plain = self.value()
        self.assertNotEqual(plain, self.value(RUSTC_WRAPPER='clippy-driver'))
        self.assertNotEqual(plain, self.value(CLIPPY_ARGS='-D__CLIPPY_HACKERY__warnings__CLIPPY_HACKERY__'))
        # The lint-only job never shares the certified build's key.
        self.assertNotEqual(plain, self.value('core-clippy', CLIPPY_RECIPE))
        self.assertNotEqual(self.value('core-clippy', CLIPPY_RECIPE),
                            self.value('core-clippy', {'commands': [['cargo', 'clippy', '--', '-W', 'x']]}))
        self.assertNotEqual(plain, self.value(RUSTUP_TOOLCHAIN='1.99.0'))

    def test_only_protected_tier_pipelines_produce(self):
        protected = {'CI_COMMIT_REF_PROTECTED': 'true'}
        self.assertEqual(cache.producer_kind(dict(protected, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='dev')), 'dev')
        self.assertEqual(cache.producer_kind(dict(protected, CI_PIPELINE_SOURCE='schedule', CI_COMMIT_BRANCH='dev')), 'qa')
        self.assertEqual(cache.producer_kind(dict(protected, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='qa')), 'qa')
        for env in ({'CI_PIPELINE_SOURCE': 'merge_request_event', 'CI_COMMIT_BRANCH': 'dev'},
                    dict(protected, CI_PIPELINE_SOURCE='api', CI_COMMIT_BRANCH='dev'),
                    {'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'qa'},
                    {'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'dev'},
                    dict(protected, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='feature')):
            self.assertIsNone(cache.producer_kind(env), env)


class Provenance(unittest.TestCase):
    MANIFEST = {'producer': {'pipeline_id': 7, 'commit': 'c' * 40, 'ref': 'dev', 'source': 'push', 'protected': True},
                'archive': {'name': 'target-7-' + 'd' * 64 + '.tar.gz', 'sha256': 'd' * 64}}
    ROW = {'package_id': 3, 'file_name': 'manifest-' + 'c' * 40 + '-7.json'}

    class Registry:
        def __init__(self, files):
            self.files = files

        def json(self, path):
            return self.files

    def files(self, **changes):
        pipeline = dict({'id': 7, 'ref': 'dev', 'source': 'push', 'sha': 'c' * 40}, **changes)
        return [{'file_name': self.ROW['file_name'], 'pipelines': [pipeline]},
                {'file_name': self.MANIFEST['archive']['name'], 'pipelines': [pipeline], 'file_sha256': 'd' * 64}]

    def test_protected_dev_push_producer_is_accepted(self):
        self.assertEqual(cache.provenance(self.Registry(self.files()), self.ROW, self.MANIFEST)['pipeline_id'], 7)

    def test_other_writers_are_misses(self):
        for changes in ({'id': 8}, {'ref': 'feature'}, {'source': 'merge_request_event'}, {'sha': 'e' * 40}):
            with self.subTest(changes=changes), self.assertRaises(Unavailable):
                cache.provenance(self.Registry(self.files(**changes)), self.ROW, self.MANIFEST)
        manifest = json.loads(json.dumps(self.MANIFEST))
        manifest['producer']['ref'] = 'feature'
        with self.assertRaises(Unavailable):
            cache.provenance(self.Registry(self.files(ref='feature')), self.ROW, manifest)
        duplicated = self.files() + self.files()[:1]
        with self.assertRaises(Unavailable):
            cache.provenance(self.Registry(duplicated), self.ROW, self.MANIFEST)
        renamed = dict(self.ROW, file_name='manifest-' + 'c' * 40 + '-8.json')
        with self.assertRaisesRegex(Unavailable, 'name'):
            cache.provenance(self.Registry(self.files()), renamed, self.MANIFEST)


class Registry:
    """In-memory generic package registry: newest file first, per-file pipelines."""

    package = cache.PACKAGE

    def __init__(self):
        self.files, self.uploads, self.deleted, self.next_id = [], [], [], 1
        self.pipeline = None

    def read(self, version, name, limit):
        for row in self.files:
            if (row['version'], row['file_name']) == (version, name):
                return row['data']
        raise FileNotFoundError(name)

    def upload(self, version, name, path):
        self.files.insert(0, {'version': version, 'file_name': name, 'data': Path(path).read_bytes(),
                              'id': self.next_id, 'pipelines': [dict(self.pipeline)]})
        self.next_id += 1
        self.uploads.append(name)

    def download(self, version, name, destination, size, digest):
        Path(destination).write_bytes(self.read(version, name, size))

    def json(self, path):
        import hashlib
        import urllib.parse
        if path.startswith('/packages?'):
            version = urllib.parse.parse_qs(path.split('?', 1)[1])['package_version'][0]
            return [{'id': 9, 'name': cache.PACKAGE, 'version': version}] if any(
                row['version'] == version for row in self.files) else []
        if '&page=' in path and '&page=1&' not in path:
            return []
        return [{'file_name': row['file_name'], 'id': row['id'], 'pipelines': row['pipelines'],
                 'file_sha256': hashlib.sha256(row['data']).hexdigest()} for row in self.files]

    def delete_package_file(self, package_id, file_id):
        row = next(row for row in self.files if row['id'] == file_id)
        self.files.remove(row)
        self.deleted.append(row['file_name'])


class RoundTrip(unittest.TestCase):
    """Producer and consumer jobs on realistic, job-specific host paths."""

    PRODUCED = 1_700_000_000_000_000_000

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.base = Path(self.dir.name)
        self.registry = Registry()
        self.sources = {'Cargo.toml': b'[workspace]\n', 'crates/a/src/lib.rs': b'a\n', 'crates/b/src/lib.rs': b'b\n'}

    def tearDown(self):
        self.dir.cleanup()

    def job(self, job_id, *, branch='dev', source='push', pipeline=None, commit='c' * 40, name='core-build',
            sources=None, recipe=BUILD_RECIPE):
        """A job laid out as the bootstrap does: /srv/.../job-<id>/store/{checkout, boundary-<p>-<id>/candidate}."""
        from native_confinement import Execution
        store = self.base / ('job-' + str(job_id)) / 'store'
        root, candidate = store / 'checkout', store / ('boundary-3-' + str(job_id)) / 'candidate'
        tree(root, sources or self.sources)
        for directory, names, files in os.walk(root):
            for item in names + files:
                os.utime(Path(directory) / item, ns=(self.PRODUCED,) * 2)
        os.utime(root, ns=(self.PRODUCED,) * 2)
        (candidate / 'target').mkdir(parents=True)
        execution = object.__new__(Execution)
        execution.roots = {'checkout': root, 'candidate': candidate}
        execution.config = {'image': 'sha256:' + 'a' * 64}
        execution.fixed_paths = {}
        execution.use_fixed_paths()

        class Q:
            pass
        q = Q()
        q.repository, q.receipt, q.save = 'GetBusbar/busbar', {'commit_ref_protected': True}, lambda: None
        q.execution, q.root, q.control = execution, root, store.parent / 'control'
        q.control.mkdir()
        q.env = {'RUSTUP_TOOLCHAIN': '1.98.0', 'RUSTC_WRAPPER': '', 'CARGO_TARGET_DIR': str(candidate / 'target')}
        pipeline = pipeline or job_id * 10
        ci = {'CI_JOB_NAME': name, 'CI_PIPELINE_SOURCE': source, 'CI_COMMIT_BRANCH': branch,
              'CI_COMMIT_REF_PROTECTED': 'true', 'CI_COMMIT_SHA': commit, 'CI_PIPELINE_ID': str(pipeline),
              'CI_JOB_ID': str(job_id)}
        self.registry.pipeline = {'id': pipeline, 'ref': branch, 'source': source, 'sha': commit}
        q.ci, q.recipe = ci, recipe
        return q

    def build(self, q, restored=None):
        target = Path(q.env['CARGO_TARGET_DIR'])
        if not (target / 'debug/deps/liba.rlib').exists():
            tree(target, {'debug/deps/liba.rlib': b'a-unit', 'debug/build/x/build-script-build': b'#!'})
            os.chmod(target / 'debug/build/x/build-script-build', 0o755)
        with patch.dict(os.environ, q.ci):
            return cache.produce(q, restored, q.recipe, self.registry)

    def restore(self, q):
        with patch.dict(os.environ, q.ci):
            return cache.restore(q, q.recipe, self.registry)

    def test_a_later_job_with_another_job_id_and_host_path_hits(self):
        producer = self.job(101)
        self.assertIsNone(self.restore(producer))
        record = self.build(producer)
        self.assertEqual(record['status'], 'published', record)
        self.assertEqual(record['generation'], 0)
        self.assertEqual(self.registry.uploads[1], 'manifest-' + 'c' * 40 + '-1010.json')
        # The key holds container paths only: no host path or job id.
        manifest = json.loads(self.registry.read(record['key'], self.registry.uploads[1], 1 << 30))
        self.assertEqual((manifest['identity']['checkout'], manifest['identity']['target_dir']),
                         ('/__busbar_checkout', '/__busbar_candidate/target'))
        self.assertNotIn('job-101', json.dumps(manifest['identity']))
        # A merge request job on a different host path, one changed file.
        changed = dict(self.sources, **{'crates/b/src/lib.rs': b'b changed\n'})
        consumer = self.job(202, source='merge_request_event', branch='', commit='e' * 40, sources=changed)
        self.assertNotEqual(consumer.root, producer.root)
        restored = self.restore(consumer)
        self.assertEqual(consumer.receipt['compile_target']['status'], 'hit', consumer.receipt)
        self.assertEqual(consumer.receipt['compile_target']['key'], record['key'])
        target = Path(consumer.env['CARGO_TARGET_DIR'])
        self.assertEqual((target / 'debug/deps/liba.rlib').read_bytes(), b'a-unit')
        self.assertTrue(os.access(target / 'debug/build/x/build-script-build', os.X_OK))
        self.assertEqual(os.stat(consumer.root / 'crates/a/src/lib.rs').st_mtime_ns, self.PRODUCED)
        self.assertGreater(os.stat(consumer.root / 'crates/b/src/lib.rs').st_mtime,
                           os.stat(target / 'debug/deps/liba.rlib').st_mtime)
        # Merge requests never write.
        consumer.receipt['commit_ref_protected'] = False
        self.assertEqual(self.build(consumer, restored)['status'], 'skipped')
        self.assertEqual(len(self.registry.uploads), 2)

    def test_the_build_and_the_lint_job_never_share_entries(self):
        build = self.job(101)
        self.restore(build)
        self.assertEqual(self.build(build)['status'], 'published')
        lint = self.job(102, name='core-clippy', recipe=CLIPPY_RECIPE)
        self.assertIsNone(self.restore(lint))
        self.assertEqual(lint.receipt['compile_target']['reasons'], [])

    def test_same_commit_is_not_published_twice_and_dev_and_qa_names_differ(self):
        dev = self.job(101)
        self.restore(dev)
        self.assertEqual(self.build(dev)['status'], 'published')
        qa = self.job(102, branch='qa', pipeline=2020)
        self.restore(qa)
        self.assertEqual(self.build(qa)['status'], 'present')
        self.assertEqual(len(self.registry.uploads), 2)
        self.assertNotEqual(cache.manifest_name('c' * 40, 1010), cache.manifest_name('c' * 40, 2020))

    def test_retention_keeps_the_newest_entries_of_a_key(self):
        for index in range(cache.RETAIN + 2):
            q = self.job(100 + index, commit=format(index, 'x') * 40)
            restored = self.restore(q)
            record = self.build(q, restored)
            self.assertEqual(record['status'], 'published', record)
        manifests = [row['file_name'] for row in self.registry.files if row['file_name'].startswith('manifest-')]
        self.assertEqual(len(manifests), cache.RETAIN)
        self.assertEqual(len(self.registry.files), 2 * cache.RETAIN)
        self.assertEqual(len(self.registry.deleted), 4)
        # An upload in flight (archive without manifest yet) is never touched.
        self.registry.pipeline = {'id': 1, 'ref': 'dev', 'source': 'push', 'sha': 'f' * 40}
        archive = self.base / 'inflight'
        archive.write_bytes(b'x')
        version = self.registry.files[0]['version']
        self.registry.upload(version, cache.archive_name(1, '0' * 64), archive)
        cache.retain(self.registry, version)
        self.assertIn(cache.archive_name(1, '0' * 64), [row['file_name'] for row in self.registry.files])

    def test_retention_never_prunes_the_dependency_unit_package(self):
        import native_dep_cache
        other = Registry()
        other.package = native_dep_cache.PACKAGE
        with self.assertRaises(Unavailable):
            cache.retain(other, 'v')
        with self.assertRaisesRegex(Unavailable, 'never pruned'):
            native_dep_cache.Registry('token').delete_package_file(1, 2)

    def test_an_exhausted_newest_entry_starts_cold_without_falling_back(self):
        q = self.job(101)
        self.restore(q)
        self.build(q)  # generation 0, older
        q = self.job(102, commit='e' * 40)
        self.restore(q)
        self.build(q, {'generation': cache.MAX_GENERATIONS - 1})  # newest at the cap
        consumer = self.job(103, commit='f' * 40)
        self.assertIsNone(self.restore(consumer))
        self.assertEqual(consumer.receipt['compile_target']['reasons'], ['compile target generation chain is exhausted'])
        self.assertFalse((Path(consumer.env['CARGO_TARGET_DIR']) / 'debug').exists())

    def test_a_changed_build_environment_after_restore_never_publishes(self):
        q = self.job(101)
        self.restore(q)
        q.env['RUSTC_WRAPPER'] = 'clippy-driver'
        record = self.build(q)
        self.assertEqual(record['status'], 'failed')
        self.assertIn('changed after', record['reason'])
        self.assertEqual(self.registry.uploads, [])

    def test_without_fixed_roots_there_is_no_cache(self):
        q = self.job(101)
        q.execution.fixed_paths = {}
        self.assertIsNone(self.restore(q))
        self.assertEqual(q.receipt['compile_target']['status'], 'fallback')
        self.assertIn('fixed', q.receipt['compile_target']['reason'])

    def test_foreign_writer_is_a_cold_start(self):
        q = self.job(101)
        self.restore(q)
        self.build(q)
        for row in self.registry.files:
            row['pipelines'] = [dict(row['pipelines'][0], ref='feature')]
        consumer = self.job(102, commit='e' * 40)
        self.assertIsNone(self.restore(consumer))


class Producer(unittest.TestCase):
    def test_merge_request_runs_never_write(self):
        class Q:
            execution, repository = object(), 'GetBusbar/busbar'
            receipt = {'commit_ref_protected': False}

            def save(self):
                pass
        with patch.dict(os.environ, {'CI_PIPELINE_SOURCE': 'merge_request_event', 'CI_COMMIT_BRANCH': ''}):
            self.assertEqual(cache.produce(Q(), None, BUILD_RECIPE, registry=object())['status'], 'skipped')


if __name__ == '__main__':
    unittest.main()
