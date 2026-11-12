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
    def test_executables_survive_pack_unpack_install(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / 'target'
            tree(target, {'debug/build/x-1/build-script-build': b'#!/bin/sh\n', 'debug/deps/liba.rlib': b'rlib'})
            os.chmod(target / 'debug/build/x-1/build-script-build', 0o755)
            os.chmod(target / 'debug/deps/liba.rlib', 0o644)
            files = cache.pack(target, base / 'a.tar.gz')
            self.assertEqual(files['debug/build/x-1/build-script-build'][1], True)
            self.assertEqual(files['debug/deps/liba.rlib'][1], False)
            seed = cache.unpack(base / 'a.tar.gz', base / 'seed', files)
            restored = time.time() - 60
            installed = cache.install(seed, base / 'job-target', restored,
                                      {name for name, row in files.items() if row[1]})
            self.assertTrue(os.access(installed / 'debug/build/x-1/build-script-build', os.X_OK))
            self.assertFalse(os.access(installed / 'debug/deps/liba.rlib', os.X_OK))
            self.assertEqual(int(os.stat(installed / 'debug/deps/liba.rlib').st_mtime), int(restored))

    def test_tampered_archive_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            tree(base / 'target', {'debug/deps/liba.rlib': b'rlib'})
            files = cache.pack(base / 'target', base / 'a.tar.gz')
            files['debug/deps/liba.rlib'][0] = '0' * 64
            with self.assertRaises(Unavailable):
                cache.unpack(base / 'a.tar.gz', base / 'seed', files)


class Identity(unittest.TestCase):
    ENV = {'RUSTUP_TOOLCHAIN': '1.98.0', 'CARGO_INCREMENTAL': '0'}

    def value(self, **env):
        return key(cache.identity('core-build', 'sha256:' + 'a' * 64, '/c', '/t', dict(self.ENV, **env)))

    def test_compiler_identity_and_lint_arguments_are_keyed(self):
        plain = self.value()
        linted = self.value(RUSTC_WRAPPER='clippy-driver', CLIPPY_ARGS='-D__CLIPPY_HACKERY__warnings__CLIPPY_HACKERY__')
        self.assertNotEqual(plain, linted)
        self.assertNotEqual(linted, self.value(RUSTC_WRAPPER='clippy-driver', CLIPPY_ARGS=''))
        self.assertNotEqual(plain, key(cache.identity('native-qualification', 'sha256:' + 'a' * 64, '/c', '/t', self.ENV)))
        self.assertNotEqual(plain, self.value(RUSTUP_TOOLCHAIN='1.99.0'))

    def test_only_protected_dev_and_qa_pipelines_produce(self):
        self.assertEqual(cache.producer_kind({'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'dev'}), 'dev')
        self.assertEqual(cache.producer_kind({'CI_PIPELINE_SOURCE': 'schedule', 'CI_COMMIT_BRANCH': 'dev'}), 'dev')
        self.assertEqual(cache.producer_kind({'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'qa',
                                              'CI_COMMIT_REF_PROTECTED': 'true'}), 'qa')
        for env in ({'CI_PIPELINE_SOURCE': 'merge_request_event', 'CI_COMMIT_BRANCH': 'dev'},
                    {'CI_PIPELINE_SOURCE': 'api', 'CI_COMMIT_BRANCH': 'dev'},
                    {'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'qa'},
                    {'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'feature'}):
            self.assertIsNone(cache.producer_kind(env), env)


class Provenance(unittest.TestCase):
    MANIFEST = {'producer': {'pipeline_id': 7, 'commit': 'c' * 40, 'ref': 'dev', 'source': 'push', 'protected': True},
                'archive': {'name': 'target-' + 'd' * 64 + '.tar.gz', 'sha256': 'd' * 64}}
    ROW = {'package_id': 3, 'file_name': 'manifest-' + 'c' * 40 + '.json'}

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
        self.assertEqual(cache.provenance(self.Registry(self.files()), 'v', self.ROW, self.MANIFEST)['pipeline_id'], 7)

    def test_other_writers_are_misses(self):
        for changes in ({'id': 8}, {'ref': 'feature'}, {'source': 'merge_request_event'}, {'sha': 'e' * 40}):
            with self.subTest(changes=changes), self.assertRaises(Unavailable):
                cache.provenance(self.Registry(self.files(**changes)), 'v', self.ROW, self.MANIFEST)
        manifest = json.loads(json.dumps(self.MANIFEST))
        manifest['producer']['ref'] = 'feature'
        with self.assertRaises(Unavailable):
            cache.provenance(self.Registry(self.files(ref='feature')), 'v', self.ROW, manifest)
        duplicated = self.files() + self.files()[:1]
        with self.assertRaises(Unavailable):
            cache.provenance(self.Registry(duplicated), 'v', self.ROW, self.MANIFEST)


class Producer(unittest.TestCase):
    def test_merge_request_runs_never_write(self):
        class Q:
            execution, repository = object(), 'GetBusbar/busbar'
            receipt = {'commit_ref_protected': False}

            def save(self):
                pass
        with patch.dict(os.environ, {'CI_PIPELINE_SOURCE': 'merge_request_event', 'CI_COMMIT_BRANCH': ''}):
            self.assertEqual(cache.produce(Q(), registry=object())['status'], 'skipped')


if __name__ == '__main__':
    unittest.main()
