"""A generated subject is an exact pinned readonly child, not another execution root."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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
        self.args = SimpleNamespace(checkout=self.subject, trusted=self.roots['trusted'],
            scratch=self.roots['harness'] / 'generated-guard', output=self.control / 'evidence.json')

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
        self.assertEqual(check.validate_execution_paths(self.args, execution, context),
                         check.generated_revision(self.subject))
        self.assertEqual(check.source_revision(self.subject), check.generated_revision(self.subject))
        # A forged child file cannot pass the independently supplied context digest.
        context['architecture_checkout']['source'] = 'generated-sha256:' + '0' * 64
        path.write_text(json.dumps(context))
        with self.assertRaises(ValueError):
            Execution.from_context(path, expected)

    def test_unregistered_descendant_and_mismatched_subject_are_refused(self):
        _, _, execution, context = self.context()
        with self.assertRaises(Violation):
            check.validate_execution_paths(self.args, execution, {})
        child = self.subject / 'nested'
        child.mkdir()
        with self.assertRaises(Violation):
            generated_architecture_context(self.engine, child, 'open-source-auth')
        for changed in (self.roots['checkout'], child, self.roots['candidate']):
            context['architecture_checkout'] = {'path': str(changed), 'source': check.generated_revision(child)}
            with self.assertRaises(Violation):
                check.validate_execution_paths(self.args, execution, context)

    def test_modified_indirect_or_git_control_source_is_refused(self):
        _, _, execution, context = self.context()
        source = self.subject / 'source.rs'
        source.write_text('changed')
        with self.assertRaises(Violation):
            check.validate_execution_paths(self.args, execution, context)
        source.unlink()
        source.symlink_to(self.subject / 'Cargo.toml')
        with self.assertRaises(Violation):
            check.generated_revision(self.subject)
        source.unlink()
        (self.subject / '.git').mkdir()
        with self.assertRaises(Violation):
            check.generated_revision(self.subject)

    def test_original_trusted_scratch_and_output_boundaries_still_apply(self):
        _, _, execution, context = self.context()
        for key, value in (('trusted', self.subject), ('scratch', self.subject),
                           ('output', self.subject / 'result.json'), ('output', self.base / 'outside.json')):
            args = SimpleNamespace(**vars(self.args))
            setattr(args, key, value)
            with self.assertRaises(Violation):
                check.validate_execution_paths(args, execution, context)

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

    def test_main_rejects_mutation_after_confined_checks(self):
        path, expected, _, _ = self.context()
        policy = self.roots['trusted'] / 'policy.toml'
        policy.write_text('version=1\n[core]\n[assembly]\npackage="fixture"\n[repositories."GetBusbar/example"]\npackages=[]\n')
        argv = ['check.py', '--policy', str(policy), '--repository', 'GetBusbar/example',
                '--checkout', str(self.subject), '--trusted', str(self.args.trusted),
                '--scratch', str(self.args.scratch), '--output', str(self.args.output),
                '--execution-context', str(path), '--execution-context-sha256', expected]
        def mutate(*_args):
            (self.subject / 'source.rs').write_text('mutated during child execution')
            return {}
        with patch('sys.argv', argv), patch.object(check, 'check_declared', return_value=[]), \
                patch.object(check, 'resolve_shipping', return_value={}), \
                patch.object(check, 'check_graph', return_value={}), \
                patch.object(check, 'check_sources', return_value={}) as sources:
            check.main()
            result = json.loads(self.args.output.read_text())
            self.assertEqual(result['source'], check.generated_revision(self.subject))
            self.assertFalse(result['release_eligible'])
            self.args.output.unlink()
            sources.side_effect = mutate
            with self.assertRaisesRegex(Violation, 'changed during qualification'):
                check.main()
        self.assertFalse(self.args.output.exists())


if __name__ == '__main__':
    unittest.main()
