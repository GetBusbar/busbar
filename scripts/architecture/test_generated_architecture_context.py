"""A generated subject is an exact pinned readonly child, not another execution root.

native_plugins builds the context and fingerprint here; busbar-ci architecture
validates them (tools/ci/src/architecture/tests.rs pins the same encoding)."""
import json
import unittest

import check
from check import Violation
from native_confinement import Execution, digest
from native_plugins import generated_architecture_context
from test_native_confinement import Fixture


class GeneratedContext(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.engine = self.execution()
        self.subject = self.roots['candidate'] / 'generated/open-source/busbar-auth-boundary-example'
        self.subject.mkdir(parents=True)
        (self.subject / 'Cargo.toml').write_text('[workspace]\n')
        (self.subject / 'source.rs').write_text('pub fn example() {}\n')
        self.engine.register_generated(self.subject)

    def context(self):
        path, expected = generated_architecture_context(self.engine, self.subject, 'open-source-auth')
        execution = Execution.from_context(path, expected)
        return path, expected, execution, json.loads(path.read_text())

    def test_registered_child_preserves_roots_config_and_readonly_mount(self):
        path, expected, execution, context = self.context()
        self.assertEqual(execution.roots, self.engine.roots)
        self.assertEqual(execution.config, self.engine.config)
        self.assertIn(self.subject, execution.extra_readonly)
        self.assertEqual(digest(path), expected)
        self.assertEqual(context['architecture_checkout'],
                         {'path': str(self.subject), 'source': check.generated_revision(self.subject)})
        # A forged child file cannot pass the independently supplied context digest.
        context['architecture_checkout']['source'] = 'generated-sha256:' + '0' * 64
        path.write_text(json.dumps(context))
        with self.assertRaises(ValueError):
            Execution.from_context(path, expected)

    def test_unregistered_descendant_is_refused(self):
        child = self.subject / 'nested'
        child.mkdir()
        with self.assertRaises(Violation):
            generated_architecture_context(self.engine, child, 'open-source-auth')

    def test_indirect_or_git_control_source_is_refused(self):
        source = self.subject / 'source.rs'
        source.unlink()
        source.symlink_to(self.subject / 'Cargo.toml')
        with self.assertRaises(Violation):
            check.generated_revision(self.subject)
        source.unlink()
        (self.subject / '.git').mkdir()
        with self.assertRaises(Violation):
            check.generated_revision(self.subject)

    def test_ambiguous_raw_concatenation_trees_and_permissions_have_distinct_fingerprints(self):
        first, second = self.base / 'first', self.base / 'second'
        first.mkdir()
        second.mkdir()
        (first / 'a').write_bytes(b'x')
        (first / 'b').write_bytes(b'y')
        (second / 'a').write_bytes(b'xb\0y')
        def old_encoding(root):
            return b''.join(str(path.relative_to(root)).encode() + b'\0' + path.read_bytes()
                            for path in sorted(root.iterdir()))
        self.assertEqual(old_encoding(first), old_encoding(second))
        self.assertNotEqual(check.generated_revision(first), check.generated_revision(second))
        before = check.generated_revision(first)
        (first / 'a').chmod(0o700)
        self.assertNotEqual(check.generated_revision(first), before)


if __name__ == '__main__':
    unittest.main()
